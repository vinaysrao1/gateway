// Package bridge adapts namespace-local HTTP to a fixed Unix socket. No Internet dialer.
package bridge

import (
	"context"
	"errors"
	"github.com/vinaysrao1/gateway/internal/localhttp"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

func Run(ctx context.Context, socket, listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host != "127.0.0.1" {
		return errors.New("bridge must bind isolated loopback")
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 8, ResponseHeaderTimeout: 30 * time.Second, DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(c, "unix", socket)
	}}
	defer tr.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.Out.URL.Scheme = "http"
		r.Out.URL.Host = "gateway.local"
		r.Out.Host = "gateway.local"
		r.Out.Header.Del("X-Forwarded-For")
		r.Out.Header.Del("X-Forwarded-Host")
		r.Out.Header.Del("X-Forwarded-Proto")
	}, Transport: tr, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, errBodyTooLarge) {
			w.WriteHeader(413)
			io.WriteString(w, `{"error":{"code":"request_too_large","message":"request_too_large"}}`)
			return
		}
		w.WriteHeader(503)
		io.WriteString(w, `{"error":{"code":"run_unavailable","message":"run_unavailable"}}`)
	}}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return errors.New("cannot bind bridge")
	}
	defer l.Close()
	// Local SDK requests are also one request per connection, bounding lifetime.
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.Method == "CONNECT" || r.Header.Get("Upgrade") != "" || len(r.Header.Values("Content-Encoding")) > 1 || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
			http.Error(w, "invalid_request", 400)
			return
		}
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-gateway-") {
				http.Error(w, "invalid_request", 400)
				return
			}
		}
		if r.ContentLength > 2<<20 {
			http.Error(w, "request_too_large", 413)
			return
		}
		if r.ContentLength != 0 {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
			r.Body = &boundedBody{ReadCloser: r.Body, w: w, max: 2 << 20}
		}
		proxy.ServeHTTP(&deadlineWriter{ResponseWriter: w}, r)
	}), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 * 1024, IdleTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	server.SetKeepAlivesEnabled(false)
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	err = server.Serve(localhttp.Bound(l, 8, 16*1024, 64, 5*time.Second))
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return errors.New("bridge failed")
}

type deadlineWriter struct{ http.ResponseWriter }

func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *deadlineWriter) Write(p []byte) (int, error) {
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(5 * time.Second))
	return w.ResponseWriter.Write(p)
}
func (w *deadlineWriter) FlushError() error {
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(5 * time.Second))
	return http.NewResponseController(w.ResponseWriter).Flush()
}

type boundedBody struct {
	io.ReadCloser
	w      http.ResponseWriter
	max, n int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.n >= b.max {
		var one [1]byte
		n, e := b.ReadCloser.Read(one[:])
		if n > 0 {
			return 0, errBodyTooLarge
		}
		if e != nil {
			_ = http.NewResponseController(b.w).SetReadDeadline(time.Time{})
		}
		return n, e
	}
	if int64(len(p)) > b.max-b.n {
		p = p[:b.max-b.n]
	}
	n, e := b.ReadCloser.Read(p)
	b.n += int64(n)
	if e != nil {
		_ = http.NewResponseController(b.w).SetReadDeadline(time.Time{})
	}
	return n, e
}

var errBodyTooLarge = errors.New("request body too large")
