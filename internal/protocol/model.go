// Package protocol validates the frozen openai-chat-v1 text/tool subset.
// It implements POL-001 and HTTP-001 without network access or tool execution.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"

	"github.com/vinaysrao1/gateway/internal/policy"
)

var invalid = errors.New("invalid model request")

// ErrModelDenied identifies a valid literal model outside the route capability.
var ErrModelDenied = errors.New("model capability denied")
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, invalid
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, invalid
	}
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, invalid
		}
	}
	return m, nil
}

func decode(raw json.RawMessage, dst any) error {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return invalid
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return invalid
	}
	return nil
}

func text(raw json.RawMessage, max int, nonempty bool) (string, error) {
	var s string
	if err := decode(raw, &s); err != nil || len(s) > max || nonempty && s == "" {
		return "", invalid
	}
	return s, nil
}

// ValidateModel validates all caller-controlled fields before admission and
// supplies the only supported output-token limit when absent.
func ValidateModel(body []byte, route policy.ModelRoute) ([]byte, bool, error) {
	if len(body) > 2<<20 || route.MaxOutputTokens < 1 || route.MaxOutputTokens > 8192 {
		return nil, false, invalid
	}
	var raw json.RawMessage
	if err := policy.DecodeStrict(body, 32, &raw); err != nil {
		return nil, false, invalid
	}
	m, err := object(raw, "model", "messages", "tools", "stream", "stream_options", "max_tokens", "temperature", "top_p", "tool_choice", "parallel_tool_calls")
	if err != nil {
		return nil, false, invalid
	}
	model, err := text(m["model"], 128, true)
	if err != nil {
		return nil, false, invalid
	}
	allowed := false
	for _, v := range route.AllowedModels {
		if model == v {
			allowed = true
		}
	}
	if !allowed {
		return nil, false, ErrModelDenied
	}
	stream := false
	if v, ok := m["stream"]; ok {
		if decode(v, &stream) != nil {
			return nil, false, invalid
		}
	}
	if v, ok := m["stream_options"]; ok {
		options, e := object(v, "include_usage")
		if e != nil || !stream {
			return nil, false, invalid
		}
		if v, ok := options["include_usage"]; ok {
			var b bool
			if decode(v, &b) != nil {
				return nil, false, invalid
			}
		}
	}
	limit := route.MaxOutputTokens
	if v, ok := m["max_tokens"]; ok {
		if decode(v, &limit) != nil || limit < 1 || limit > route.MaxOutputTokens {
			return nil, false, invalid
		}
	}
	m["max_tokens"], _ = json.Marshal(limit)
	for key, max := range map[string]float64{"temperature": 2, "top_p": 1} {
		if v, ok := m[key]; ok {
			var n float64
			if decode(v, &n) != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > max {
				return nil, false, invalid
			}
		}
	}
	if v, ok := m["parallel_tool_calls"]; ok {
		var b bool
		if decode(v, &b) != nil {
			return nil, false, invalid
		}
	}
	tools := make(map[string]bool)
	if v, ok := m["tools"]; ok {
		var declarations []json.RawMessage
		if decode(v, &declarations) != nil || len(declarations) > 64 {
			return nil, false, invalid
		}
		for _, v := range declarations {
			d, e := object(v, "type", "function")
			if e != nil {
				return nil, false, invalid
			}
			kind, e := text(d["type"], 16, true)
			if e != nil || kind != "function" {
				return nil, false, invalid
			}
			f, e := object(d["function"], "name", "description", "parameters", "strict")
			if e != nil {
				return nil, false, invalid
			}
			name, e := text(f["name"], 64, true)
			if e != nil || !namePattern.MatchString(name) || tools[name] {
				return nil, false, invalid
			}
			tools[name] = true
			if v, ok := f["description"]; ok {
				if _, e := text(v, 4096, false); e != nil {
					return nil, false, invalid
				}
			}
			if v, ok := f["strict"]; ok {
				var b bool
				if decode(v, &b) != nil {
					return nil, false, invalid
				}
			}
			if v, ok := f["parameters"]; ok {
				if !validSchema(v) {
					return nil, false, invalid
				}
			}
		}
	}
	if v, ok := m["tool_choice"]; ok {
		var choice string
		if json.Unmarshal(v, &choice) == nil && !bytes.Equal(v, []byte("null")) {
			if choice != "auto" && choice != "none" && choice != "required" {
				return nil, false, invalid
			}
			if choice == "required" && len(tools) == 0 {
				return nil, false, invalid
			}
		} else {
			c, e := object(v, "type", "function")
			if e != nil {
				return nil, false, invalid
			}
			kind, e := text(c["type"], 16, true)
			if e != nil || kind != "function" {
				return nil, false, invalid
			}
			f, e := object(c["function"], "name")
			if e != nil {
				return nil, false, invalid
			}
			name, e := text(f["name"], 64, true)
			if e != nil || !tools[name] {
				return nil, false, invalid
			}
		}
	}
	var messages []json.RawMessage
	if decode(m["messages"], &messages) != nil || len(messages) < 1 || len(messages) > 1024 {
		return nil, false, invalid
	}
	calls := make(map[string]bool)
	for _, v := range messages {
		msg, e := object(v, "role", "content", "name", "tool_calls", "tool_call_id")
		if e != nil {
			return nil, false, invalid
		}
		role, e := text(msg["role"], 16, true)
		if e != nil {
			return nil, false, invalid
		}
		if v, ok := msg["name"]; ok {
			name, e := text(v, 64, true)
			if e != nil || !namePattern.MatchString(name) {
				return nil, false, invalid
			}
		}
		_, hasCalls := msg["tool_calls"]
		_, hasID := msg["tool_call_id"]
		if hasCalls && role != "assistant" || hasID && role != "tool" {
			return nil, false, invalid
		}
		switch role {
		case "system", "developer", "user", "assistant", "tool":
		default:
			return nil, false, invalid
		}
		content, exists := msg["content"]
		if !exists {
			return nil, false, invalid
		}
		if bytes.Equal(content, []byte("null")) {
			if role != "assistant" || !hasCalls {
				return nil, false, invalid
			}
		} else {
			if !validContent(content) {
				return nil, false, invalid
			}
		}
		if hasCalls {
			var list []json.RawMessage
			if decode(msg["tool_calls"], &list) != nil || len(list) < 1 || len(list) > 64 {
				return nil, false, invalid
			}
			for _, v := range list {
				call, e := object(v, "id", "type", "function")
				if e != nil {
					return nil, false, invalid
				}
				id, e := text(call["id"], 128, true)
				if e != nil || calls[id] {
					return nil, false, invalid
				}
				kind, e := text(call["type"], 16, true)
				if e != nil || kind != "function" {
					return nil, false, invalid
				}
				f, e := object(call["function"], "name", "arguments")
				if e != nil {
					return nil, false, invalid
				}
				name, e := text(f["name"], 64, true)
				if e != nil || !tools[name] {
					return nil, false, invalid
				}
				args, e := text(f["arguments"], 2<<20, false)
				if e != nil {
					return nil, false, invalid
				}
				var argJSON json.RawMessage
				if policy.DecodeStrict([]byte(args), 32, &argJSON) != nil {
					return nil, false, invalid
				}
				calls[id] = true
			}
		}
		if role == "tool" {
			id, e := text(msg["tool_call_id"], 128, true)
			if e != nil || !calls[id] {
				return nil, false, invalid
			}
		}
	}
	normalized, e := json.Marshal(m)
	if e != nil {
		return nil, false, invalid
	}
	return normalized, stream, nil
}

func validContent(raw json.RawMessage) bool {
	if _, err := text(raw, 2<<20, false); err == nil {
		return true
	}
	var blocks []json.RawMessage
	if decode(raw, &blocks) != nil || len(blocks) < 1 || len(blocks) > 64 {
		return false
	}
	for _, raw := range blocks {
		block, err := object(raw, "type", "text")
		if err != nil {
			return false
		}
		kind, err := text(block["type"], 16, true)
		if err != nil || kind != "text" {
			return false
		}
		if _, err := text(block["text"], 2<<20, false); err != nil {
			return false
		}
	}
	return true
}

func validSchema(raw []byte) bool {
	var schema map[string]any
	if policy.DecodeStrict(raw, 16, &schema) != nil || schema == nil {
		return false
	}
	var visit func(any) bool
	visit = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				if k == "$ref" || k == "$dynamicRef" || k == "$recursiveRef" {
					s, ok := v.(string)
					if !ok || !strings.HasPrefix(s, "#") {
						return false
					}
				}
				if !visit(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !visit(v) {
					return false
				}
			}
		}
		return true
	}
	return visit(schema)
}
