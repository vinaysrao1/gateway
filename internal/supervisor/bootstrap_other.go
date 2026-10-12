//go:build !linux

package supervisor

import (
	"context"
	"github.com/vinaysrao1/gateway/internal/isolation"
)

func Bootstrap(context.Context, []string) error { return isolation.ErrUnsupported }
