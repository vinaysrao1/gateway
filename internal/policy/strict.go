package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// MaxJSONItems bounds parser allocation amplification from many tiny members.
// Every value (including a container) and every object key consumes one item.
const MaxJSONItems = 8192

// DecodeStrict rejects invalid UTF-8, duplicate keys at every depth, excess
// nesting, unknown struct fields, and trailing data before assigning to dst.
func DecodeStrict(data []byte, maxDepth int, dst any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid JSON encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	remaining := MaxJSONItems
	if err := scanValue(d, 0, maxDepth, &remaining); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	if err := exactFields(data, reflect.TypeOf(dst)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}

// encoding/json matches struct fields case-insensitively. Policy keys are
// exact schema tokens, so perform this check before ordinary struct decoding.
func exactFields(raw []byte, typ reflect.Type) error {
	if typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return errors.New("invalid JSON object")
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if name != "-" {
				fields[name] = f.Type
			}
		}
		for key, value := range obj {
			field, ok := fields[key]
			if !ok {
				return errors.New("unknown JSON field")
			}
			if err := exactFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return errors.New("invalid JSON array")
		}
		for _, value := range values {
			if err := exactFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return errors.New("invalid JSON object")
		}
		for _, value := range values {
			if err := exactFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanValue(d *json.Decoder, depth, maxDepth int, remaining *int) error {
	*remaining--
	if *remaining < 0 {
		return errors.New("JSON item limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	delim, composite := t.(json.Delim)
	if !composite {
		return nil
	}
	if depth >= maxDepth {
		return errors.New("JSON nesting limit exceeded")
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for d.More() {
			*remaining--
			if *remaining < 0 {
				return errors.New("JSON item limit exceeded")
			}
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid JSON object")
			}
			s, ok := key.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			if _, exists := keys[s]; exists {
				return errors.New("duplicate JSON key")
			}
			keys[s] = struct{}{}
			if err := scanValue(d, depth+1, maxDepth, remaining); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1, maxDepth, remaining); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
