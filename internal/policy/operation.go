package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Operation carries fixed, immutable policy authority. Its zero value carries
// no authority. Only a validated Policy can construct a usable operation.
type Operation struct {
	url, method, credential string
	body                    []byte
	stream                  bool
}

func (o Operation) URL() string        { return o.url }
func (o Operation) Method() string     { return o.method }
func (o Operation) Body() []byte       { return append([]byte(nil), o.body...) }
func (o Operation) Credential() string { return o.credential }
func (o Operation) Stream() bool       { return o.stream }

// Format keeps credentials and bodies out of accidental generic logging,
// including reflection-style %+v and %#v formatting of this private value.
func (o Operation) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "authorized operation")
}

// AuthorizeModel binds a normalized, protocol-validated request to this policy's
// exact model endpoint. Caller identity claims never select a destination or key.
// The broker must run protocol.ValidateModel before requesting this operation.
func (p *Policy) AuthorizeModel(body []byte, credential string, stream bool) (Operation, error) {
	denied := errors.New("model capability denied")
	if p.model == nil || int64(len(body)) > p.limits.RequestBytes || credential == "" || strings.ContainsAny(credential, "\r\n\x00") {
		return Operation{}, denied
	}
	var fields map[string]json.RawMessage
	if DecodeStrict(body, 32, &fields) != nil {
		return Operation{}, denied
	}
	var model string
	if json.Unmarshal(fields["model"], &model) != nil {
		return Operation{}, denied
	}
	allowed := false
	for _, m := range p.model.AllowedModels {
		if model == m {
			allowed = true
		}
	}
	if !allowed {
		return Operation{}, denied
	}
	var limit int64
	if json.Unmarshal(fields["max_tokens"], &limit) != nil || limit < 1 || limit > p.model.MaxOutputTokens {
		return Operation{}, denied
	}
	requestStream := false
	if raw, ok := fields["stream"]; ok {
		if string(raw) == "null" || json.Unmarshal(raw, &requestStream) != nil {
			return Operation{}, denied
		}
	}
	if stream != requestStream {
		return Operation{}, denied
	}
	return Operation{url: p.model.UpstreamURL, method: "POST", body: append([]byte(nil), body...), credential: credential, stream: stream}, nil
}

func (p *Policy) AuthorizeFetch(id string) (Operation, error) {
	resource, ok := p.fetch[id]
	if !ok {
		return Operation{}, errors.New("fetch capability denied")
	}
	return Operation{url: resource.URL, method: "GET"}, nil
}
