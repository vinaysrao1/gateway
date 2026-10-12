package audit

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

type broken struct{}

func (broken) Write([]byte) (int, error) { return 0, errors.New("secret failure") }
func TestFailureLatches(t *testing.T) {
	l, _ := New(broken{}, 2048, 8192)
	for range 2 {
		if err := l.Record(Event{Kind: "admit"}); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal(err)
		}
	}
}
func TestBoundedConcurrentRecords(t *testing.T) {
	var out bytes.Buffer
	l, _ := New(&out, 2048, 8192)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Record(Event{Kind: "admit"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if bytes.Count(out.Bytes(), []byte{'\n'}) != 20 {
		t.Fatal(out.String())
	}
	large := Event{Kind: strings.Repeat("x", 2048)}
	if l.Record(large) == nil || l.Record(Event{Kind: "admit"}) == nil {
		t.Fatal("must fail closed")
	}
}
