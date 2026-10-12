package broker

import (
	"context"
	"errors"
	"github.com/vinaysrao1/gateway/internal/localhttp"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"time"
)

// Serve is local-only. The parent directory must be private and trusted.
func (s *Server) Serve(ctx context.Context, path string) error {
	parent, err := os.Stat(directory(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return errors.New("socket directory must be private")
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return errors.New("cannot create socket")
	}
	defer l.Close()
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		return errors.New("cannot protect socket")
	}
	limits := s.policy.Limits()
	guard := localhttp.Bound(l, int(limits.LocalConnections), int(limits.HeaderBytes), int(limits.HeaderCount), time.Duration(limits.ReadHeaderSeconds)*time.Second)
	server := &http.Server{Handler: s, ReadHeaderTimeout: time.Duration(limits.ReadHeaderSeconds) * time.Second, MaxHeaderBytes: int(limits.HeaderBytes), IdleTimeout: time.Duration(limits.ReadHeaderSeconds) * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	server.SetKeepAlivesEnabled(false)
	stop := context.AfterFunc(ctx, func() { s.Close(); server.Close() })
	defer stop()
	stopRun := context.AfterFunc(s.ctx, func() { server.Close() })
	defer stopRun()
	err = server.Serve(guard)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return errors.New("local server failed")
}
func directory(path string) string {
	at := strings.LastIndex(path, "/")
	if at < 0 {
		return "."
	}
	if at == 0 {
		return "/"
	}
	return path[:at]
}
