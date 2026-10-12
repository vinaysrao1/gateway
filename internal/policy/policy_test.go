package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	v := map[string]any{"schema_version": 1, "limits": DefaultLimits(), "model_routes": []ModelRoute{{ID: "model", LocalPath: "/v1/chat/completions", UpstreamURL: "https://api.example.com/v1/chat/completions", Protocol: "openai-chat-v1", AllowedModels: []string{"test-model"}, CredentialRef: "model-key", MaxOutputTokens: 512}}, "fetch_resources": []FetchResource{{ID: "docs", URL: "https://docs.example.com/guide"}}, "denied_cidrs": []string{"8.8.8.0/24"}}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// POL-002: neither source-byte mutation nor returned collections change authority.
func TestSnapshotImmutability(t *testing.T) {
	data := fixture(t)
	hash := sha256.Sum256(data)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest() != hex.EncodeToString(hash[:]) {
		t.Fatal("digest must hash exact source bytes")
	}
	for i := range data {
		data[i] = 'x'
	}
	r, ok := p.Model()
	if !ok {
		t.Fatal("missing model")
	}
	r.AllowedModels[0] = "attacker"
	d := p.DeniedCIDRs()
	d[0] = netip.MustParsePrefix("0.0.0.0/0")
	l := p.Limits()
	l.TotalOperations = 99999
	r, _ = p.Model()
	if r.AllowedModels[0] != "test-model" || p.DeniedCIDRs()[0].String() != "8.8.8.0/24" || p.Limits().TotalOperations != 500 {
		t.Fatal("snapshot mutated")
	}
	if _, ok := p.Fetch("unknown"); ok {
		t.Fatal("unknown resource authorized")
	}
}

func TestInvalidPolicies(t *testing.T) {
	base := string(fixture(t))
	cases := map[string]string{
		"wrong key case":       strings.Replace(base, `"schema_version":1`, `"SCHEMA_VERSION":1`, 1),
		"wrong nested case":    strings.Replace(base, `"id":"docs"`, `"ID":"docs"`, 1),
		"unknown":              strings.Replace(base, `"schema_version":1`, `"schema_version":1,"extra":true`, 1),
		"duplicate root":       strings.Replace(base, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		"duplicate nested":     strings.Replace(base, `"id":"docs"`, `"id":"docs","id":"docs"`, 1),
		"escaped duplicate":    strings.Replace(base, `"id":"docs"`, `"id":"docs","\u0069d":"docs"`, 1),
		"unknown nested":       strings.Replace(base, `"id":"docs"`, `"id":"docs","headers":{}`, 1),
		"version":              strings.Replace(base, `"schema_version":1`, `"schema_version":2`, 1),
		"missing limit":        strings.Replace(base, `"run_seconds":1800,`, "", 1),
		"null limit":           strings.Replace(base, `"run_seconds":1800`, `"run_seconds":null`, 1),
		"oversize limit":       strings.Replace(base, `"request_bytes":2097152`, `"request_bytes":2097153`, 1),
		"duplicate ID":         strings.Replace(base, `"id":"docs"`, `"id":"model"`, 1),
		"model list duplicate": strings.Replace(base, `"test-model"`, `"test-model","test-model"`, 1),
		"noncanonical CIDR":    strings.Replace(base, `8.8.8.0/24`, `8.8.8.1/24`, 1),
		"trailing":             base + ` {}`,
		"too big":              base + strings.Repeat(" ", MaxPolicyBytes),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

// DST-001: hostile URL grammar cannot produce even a valid policy capability.
func TestCanonicalDestinations(t *testing.T) {
	valid := []string{"https://api.example.com/", "https://xn--bcher-kva.example/path_a-1/~b"}
	for _, u := range valid {
		if err := ValidateURL(u); err != nil {
			t.Errorf("valid URL %q: %v", u, err)
		}
	}
	invalid := []string{"http://api.example.com/", "https://user@api.example.com/", "https://api.example.com:443/", "https://api.example.com:80/", "https://api.example.com./", "https://API.example.com/", "https://api.example.com/?", "https://api.example.com/?q=x", "https://api.example.com/#x", "https://127.0.0.1/", "https://[::1]/", "https://[fe80::1%25eth0]/", "https://bücher.example/", "https://api.example.com/%2e", "https://api.example.com/a/../b", "https://api.example.com/a/./b", "https://api.example.com//b", "https://api.example.com/a\\b", "https://-bad.example/", "https://bad-.example/", "https://api..example/", "https://api.example.com/a b", "https://api.example.com\n/", "https://*.example.com/", "https://api.example.com"}
	for _, u := range invalid {
		if err := ValidateURL(u); err == nil {
			t.Errorf("invalid URL accepted: %q", u)
		}
	}
}

func TestStrictJSON(t *testing.T) {
	for _, input := range [][]byte{[]byte(`{"a":{"b":1,"b":2}}`), []byte(`{"a":1} true`), []byte(`{"a":`), {0xff}, []byte(strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33))} {
		var dst any
		if DecodeStrict(input, 32, &dst) == nil {
			t.Errorf("invalid JSON accepted: %q", input)
		}
	}
	var dst any
	if err := DecodeStrict([]byte(strings.Repeat("[", 32)+"0"+strings.Repeat("]", 32)), 32, &dst); err != nil {
		t.Fatal(err)
	}
}

func TestStrictJSONItemEnvelope(t *testing.T) {
	var dst any
	// An array itself consumes one item, so exactly8191 scalar values fit.
	valid := "[" + strings.TrimSuffix(strings.Repeat("0,", MaxJSONItems-1), ",") + "]"
	if err := DecodeStrict([]byte(valid), 32, &dst); err != nil {
		t.Fatal("boundary rejected", err)
	}
	invalid := "[" + strings.TrimSuffix(strings.Repeat("0,", MaxJSONItems), ",") + "]"
	if err := DecodeStrict([]byte(invalid), 32, &dst); err == nil {
		t.Fatal("item envelope exceeded")
	}
}

func TestOperationAuthorityAndImmutability(t *testing.T) {
	p, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"test-model","max_tokens":512,"messages":[{"role":"user","content":"hi"}]}`)
	op, err := p.AuthorizeModel(body, "canary", false)
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 'x'
	copyBody := op.Body()
	copyBody[0] = 'x'
	if op.URL() != "https://api.example.com/v1/chat/completions" || op.Method() != "POST" || op.Credential() != "canary" || op.Body()[0] != '{' {
		t.Fatal("authority mutated")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, op); strings.Contains(got, "canary") || strings.Contains(got, "test-model") {
			t.Fatal("generic formatting leaks private data", got)
		}
	}
	fetch, err := p.AuthorizeFetch("docs")
	if err != nil || fetch.Credential() != "" || len(fetch.Body()) != 0 || fetch.Method() != "GET" {
		t.Fatal("fetch gained model authority")
	}
	if _, err := p.AuthorizeFetch("unknown"); err == nil {
		t.Fatal("unknown fetch authorized")
	}
	for _, body := range []string{`{"model":"unknown","max_tokens":1}`, `{"model":"test-model"}`, `{"model":"test-model","max_tokens":513}`, `{"model":"test-model","max_tokens":1,"stream":true}`} {
		if _, err := p.AuthorizeModel([]byte(body), "canary", false); err == nil {
			t.Fatal("invalid model operation authorized")
		}
	}
}

func FuzzParsePolicy(f *testing.F) {
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"schema_version":1,"schema_version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err == nil {
			if p.Digest() == "" {
				t.Fatal("accepted policy lacks digest")
			}
			if err := p.Limits().Validate(); err != nil {
				t.Fatal(err)
			}
		}
	})
}
