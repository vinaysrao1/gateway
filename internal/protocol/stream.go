package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Completion observes bounded SSE events without changing streamed bytes.
// STREAM-001: clean HTTP EOF does not itself prove model completion.
type Completion struct {
	line, data   []byte
	finish, done bool
	previousCR   bool
}

const MaxSSEEventBytes = 64 << 10

func (c *Completion) Feed(p []byte) error {
	for _, b := range p {
		if c.previousCR {
			c.previousCR = false
			if b == '\n' {
				continue
			}
		}
		if b != '\n' && b != '\r' {
			if len(c.line) >= MaxSSEEventBytes {
				return errors.New("oversized stream event")
			}
			c.line = append(c.line, b)
			continue
		}
		c.previousCR = b == '\r'
		line := c.line
		c.line = nil
		if len(line) == 0 {
			if len(c.data) > 0 {
				if e := c.event(); e != nil {
					return e
				}
				c.data = nil
			}
			continue
		}
		if line[0] == ':' {
			continue
		}
		name, value, ok := bytes.Cut(line, []byte{':'})
		if !ok || string(name) != "data" {
			continue
		}
		value = bytes.TrimPrefix(value, []byte{' '})
		if len(c.data)+len(value)+1 > MaxSSEEventBytes {
			return errors.New("oversized stream event")
		}
		if len(c.data) > 0 {
			c.data = append(c.data, '\n')
		}
		c.data = append(c.data, value...)
	}
	return nil
}
func (c *Completion) event() error {
	if c.done {
		return errors.New("event after terminal stream marker")
	}
	if string(c.data) == "[DONE]" {
		if !c.finish {
			return errors.New("stream ended without finish reason")
		}
		c.done = true
		return nil
	}
	var event struct {
		Choices []struct {
			Index        int     `json:"index"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(c.data, &event) != nil {
		return errors.New("invalid stream event")
	}
	if len(event.Choices) > 1 {
		return errors.New("multiple stream choices unsupported")
	}
	for _, choice := range event.Choices {
		if choice.Index != 0 {
			return errors.New("nonzero stream choice unsupported")
		}
		if choice.FinishReason != nil && strings.TrimSpace(*choice.FinishReason) != "" {
			switch *choice.FinishReason {
			case "stop", "length", "tool_calls":
			default:
				return errors.New("unsupported stream finish reason")
			}
			c.finish = true
		}
	}
	return nil
}
func (c *Completion) Finished() bool {
	return c.done && c.finish && len(c.line) == 0 && len(c.data) == 0
}

func (c *Completion) TerminalSeen() bool { return c.done }
