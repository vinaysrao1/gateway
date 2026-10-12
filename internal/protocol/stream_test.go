package protocol

import (
	"strings"
	"testing"
)

func TestStreamCompletionRequiresFinishAndTerminal(t *testing.T) {
	complete := "data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	for _, tc := range []struct {
		data     string
		finished bool
	}{{complete, true}, {"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", false}, {"data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\n", false}} {
		var c Completion
		for _, b := range []byte(tc.data) {
			if e := c.Feed([]byte{b}); e != nil {
				t.Fatal(e)
			}
		}
		if c.Finished() != tc.finished {
			t.Fatal(tc.data, c.Finished())
		}
	}
	for _, input := range []string{"data: [DONE]\n\n", complete + "data: {}\n\n", "data: invalid\n\n", "data: " + strings.Repeat("x", MaxSSEEventBytes) + "\n\n"} {
		var c Completion
		if c.Feed([]byte(input)) == nil {
			t.Fatal("accepted invalid stream")
		}
	}
}

func TestOtherChoiceCannotCompleteFirstChoice(t *testing.T) {
	for _, data := range []string{`{"choices":[{"index":0,"finish_reason":null},{"index":1,"finish_reason":"stop"}]}`, `{"choices":[{"index":1,"finish_reason":"stop"}]}`} {
		var c Completion
		if c.Feed([]byte("data: "+data+"\n\n")) == nil {
			t.Fatal("accepted other-choice completion")
		}
	}
}

func TestAllSDKNewlineDelimiters(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n", "\r"} {
		wire := "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}" + newline + newline + "data: [DONE]" + newline + newline
		var c Completion
		for i, b := range []byte(wire) {
			if e := c.Feed([]byte{b}); e != nil {
				t.Fatal(e)
			}
			if c.TerminalSeen() && i < len(wire)-len(newline) {
				t.Fatal("early terminal observation")
			}
		}
		if !c.Finished() {
			t.Fatal("delimiter mismatch", newline)
		}
	}
}
