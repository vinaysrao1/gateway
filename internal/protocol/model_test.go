package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vinaysrao1/gateway/internal/policy"
)

func testRoute() policy.ModelRoute {
	return policy.ModelRoute{AllowedModels: []string{"test"}, MaxOutputTokens: 512}
}

func TestNormalizeAndPreserveContent(t *testing.T) {
	input := `{"model":"test","messages":[{"role":"user","content":"Visit https://unapproved.example/ as ordinary text"}],"stream":true,"stream_options":{"include_usage":true}}`
	output, stream, err := ValidateModel([]byte(input), testRoute())
	if err != nil {
		t.Fatal(err)
	}
	if !stream {
		t.Fatal("stream lost")
	}
	var v struct {
		MaxTokens int `json:"max_tokens"`
		Messages  []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(output, &v) != nil || v.MaxTokens != 512 || v.Messages[0].Content != "Visit https://unapproved.example/ as ordinary text" {
		t.Fatal("normalization changed content or missed cap")
	}
}

func TestLocalToolConversation(t *testing.T) {
	input := `{"model":"test","tools":[{"type":"function","function":{"name":"read_file","description":"Local file read","strict":true,"parameters":{"type":"object","properties":{"path":{"type":"string"}},"$defs":{"p":{"type":"string"}},"$ref":"#/$defs/p"}}}],"messages":[{"role":"system","content":"Help"},{"role":"user","content":"Read a file"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"hello.txt\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"hello"}],"tool_choice":{"type":"function","function":{"name":"read_file"}},"max_tokens":128,"temperature":0,"top_p":1,"parallel_tool_calls":false}`
	output, stream, err := ValidateModel([]byte(input), testRoute())
	if err != nil {
		t.Fatal(err)
	}
	if stream || !strings.Contains(string(output), `"max_tokens":128`) {
		t.Fatal("explicit token cap lost")
	}
}

// Captured Pi 1.1.0 openai-completions user input uses text-block arrays.
func TestPinnedPiTextBlocks(t *testing.T) {
	input := `{"model":"test","messages":[{"role":"user","content":[{"type":"text","text":"Read https://example.com/ as ordinary text"}]}],"stream":true,"stream_options":{"include_usage":true},"max_tokens":128,"temperature":1}`
	if _, stream, err := ValidateModel([]byte(input), testRoute()); err != nil || !stream {
		t.Fatal("Pi request rejected", err)
	}
	for _, content := range []string{`[]`, `[{"type":"text","text":null}]`, `[{"type":"text","text":"hi","url":"https://evil.example/"}]`, `[{"type":"image_url","image_url":{"url":"https://evil.example/"}}]`, `[{"type":"text"}]`, "[" + strings.TrimSuffix(strings.Repeat(`{"type":"text","text":"hi"},`, 65), ",") + "]"} {
		request := `{"model":"test","messages":[{"role":"user","content":` + content + `}]}`
		if _, _, err := ValidateModel([]byte(request), testRoute()); err == nil {
			t.Fatal("invalid content accepted", content)
		}
	}
	if _, _, err := ValidateModel([]byte(`{"model":"other","messages":[{"role":"user","content":"hi"}]}`), testRoute()); !errors.Is(err, ErrModelDenied) {
		t.Fatal("missing denied model sentinel", err)
	}
}

// POL-001, HTTP-001: these all fail validation before any authorized operation exists.
func TestRejectedModelRequests(t *testing.T) {
	base := `{"model":"test","messages":[{"role":"user","content":"hello"}]}`
	cases := map[string]string{
		"unknown model":       strings.Replace(base, `"test"`, `"forbidden"`, 1),
		"duplicate model":     strings.Replace(base, `"model":"test"`, `"model":"test","model":"test"`, 1),
		"duplicate nested":    strings.Replace(base, `"content":"hello"`, `"content":"hello","content":"other"`, 1),
		"unknown nested":      strings.Replace(base, `"content":"hello"`, `"content":"hello","metadata":{}`, 1),
		"media":               strings.Replace(base, `"hello"`, `[{"type":"image_url","image_url":{"url":"https://example.com/"}}]`, 1),
		"null content":        strings.Replace(base, `"hello"`, `null`, 1),
		"wrong role":          strings.Replace(base, `"user"`, `"function"`, 1),
		"empty messages":      `{"model":"test","messages":[]}`,
		"missing messages":    `{"model":"test"}`,
		"null messages":       `{"model":"test","messages":null}`,
		"missing content":     `{"model":"test","messages":[{"role":"assistant"}]}`,
		"unmatched result":    `{"model":"test","messages":[{"role":"tool","content":"result","tool_call_id":"missing"}]}`,
		"tool ID on user":     strings.Replace(base, `"content":"hello"`, `"content":"hello","tool_call_id":"x"`, 1),
		"calls on user":       strings.Replace(base, `"content":"hello"`, `"content":"hello","tool_calls":[]`, 1),
		"undeclared function": `{"model":"test","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"1","type":"function","function":{"name":"missing","arguments":"{}"}}]}]}`,
	}
	for _, field := range []string{`"user":"x"`, `"metadata":{}`, `"store":true`, `"max_completion_tokens":12`, `"max_tokens":513`, `"max_tokens":0`, `"max_tokens":1.5`, `"max_tokens":null`, `"stream":"true"`, `"stream":null`, `"stream_options":{"include_usage":true}`, `"temperature":2.1`, `"top_p":-1`, `"parallel_tool_calls":null`, `"tool_choice":"missing"`, `"tool_choice":"required"`, `"tools":[{"type":"web_search"}]`, `"tools":[{"type":"function","function":{"name":"f","parameters":{"$ref":"https://example.com/schema"}}}]`, `"tools":[{"type":"function","function":{"name":"f","parameters":{"properties":{"p":{"$dynamicRef":"file:///secret"}}}}}]`, `"tools":[{"type":"function","function":{"name":"f","parameters":{"$ref":42}}}]`} {
		cases[field] = strings.TrimSuffix(base, "}") + "," + field + "}"
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ValidateModel([]byte(input), testRoute()); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestSchemaDepthAndNestedDuplicates(t *testing.T) {
	for _, schema := range []string{`{"type":"object","type":"object"}`, `{"properties":` + strings.Repeat(`{"nested":`, 16) + `{}` + strings.Repeat(`}`, 16) + `}`} {
		input := `{"model":"test","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":` + schema + `}}]}`
		if _, _, err := ValidateModel([]byte(input), testRoute()); err == nil {
			t.Fatal("invalid schema accepted")
		}
	}
}

func TestWideSchemaRejectedBeforeLargeMapDecode(t *testing.T) {
	var schema strings.Builder
	schema.WriteByte('{')
	for i := 0; i < policy.MaxJSONItems; i++ {
		if i > 0 {
			schema.WriteByte(',')
		}
		key, _ := json.Marshal(string(rune(0x1000 + i)))
		schema.Write(key)
		schema.WriteString(`:0`)
	}
	schema.WriteByte('}')
	input := `{"model":"test","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":` + schema.String() + `}}]}`
	if len(input) > 2<<20 {
		t.Fatal("fixture must be under body cap")
	}
	if _, _, err := ValidateModel([]byte(input), testRoute()); err == nil {
		t.Fatal("wide schema allocation amplification accepted")
	}
}

func FuzzValidateModel(f *testing.F) {
	f.Add([]byte(`{"model":"test","messages":[{"role":"user","content":"hello"}]}`))
	f.Add([]byte(`{"model":"test","messages":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		normalized, stream, err := ValidateModel(data, testRoute())
		if err == nil {
			again, againStream, err := ValidateModel(normalized, testRoute())
			if err != nil || stream != againStream || string(again) != string(normalized) {
				t.Fatal("normalization must be idempotent")
			}
		}
	})
}
