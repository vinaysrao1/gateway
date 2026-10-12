//go:build !linux

package isolation

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformFailsClosed(t *testing.T) {
	if jail, err := Prepare(Config{Command: []string{"/bin/sh"}}); jail != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unexpected fallback: %v %v", jail, err)
	}
}
