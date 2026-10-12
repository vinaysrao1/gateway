// Package transport owns all production Internet resolution and dialing.
// DST-002/DST-003: a checked DNS answer is pinned to one TLS connection and one
// HTTP/1.1 request, without proxies, pooling, redirects, or replay.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vinaysrao1/gateway/internal/policy"
)

var (
	ErrDestinationDenied = errors.New("destination denied")
	ErrUpstream          = errors.New("upstream failed")
	ErrDeadline          = errors.New("deadline exceeded")
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Options contains trusted construction-time settings. Resolver, DialContext,
// and TLSRoots enable isolated fixtures; the production launcher does not expose
// these as policy options. No option disables address checks or TLS verification.
type Options struct {
	Resolver                                   Resolver
	DialContext                                func(context.Context, string, string) (net.Conn, error)
	TLSRoots                                   *x509.CertPool
	DeniedCIDRs                                []netip.Prefix
	DNSTimeout, ConnectTimeout, TLSTimeout     time.Duration
	HeaderTimeout, IdleTimeout, OverallTimeout time.Duration
}

type Transport struct{ opts Options }

// Operation is constructed by trusted policy admission, never from a local URL
// parameter. The broker owns quotas and the admission-before-egress audit rule.
type Operation = policy.Operation

func New(o Options) (*Transport, error) {
	for _, p := range o.DeniedCIDRs {
		if !p.IsValid() || p.Addr().Is4In6() {
			return nil, ErrDestinationDenied
		}
	}
	o.DeniedCIDRs = append([]netip.Prefix(nil), o.DeniedCIDRs...)
	if o.Resolver == nil {
		o.Resolver = &net.Resolver{PreferGo: true}
	}
	if o.DialContext == nil {
		o.DialContext = (&net.Dialer{}).DialContext
	}
	for _, pair := range []struct {
		p *time.Duration
		d time.Duration
	}{
		{&o.DNSTimeout, 3 * time.Second}, {&o.ConnectTimeout, 5 * time.Second},
		{&o.TLSTimeout, 5 * time.Second}, {&o.HeaderTimeout, 30 * time.Second},
		{&o.IdleTimeout, 30 * time.Second},
	} {
		if *pair.p < 0 {
			return nil, ErrUpstream
		}
		if *pair.p == 0 {
			*pair.p = pair.d
		}
	}
	if o.OverallTimeout < 0 {
		return nil, ErrUpstream
	}
	if o.TLSRoots != nil {
		o.TLSRoots = o.TLSRoots.Clone()
	}
	return &Transport{opts: o}, nil
}

func (t *Transport) Do(parent context.Context, op Operation) (*http.Response, error) {
	body, credential := op.Body(), op.Credential()
	// Defense in depth. Admission additionally validates the full canonical grammar.
	u, err := url.Parse(op.URL())
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Host != u.Hostname() || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(u.Host, "\\\r\n\x00") || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ".") {
		return nil, ErrDestinationDenied
	}
	if _, e := netip.ParseAddr(u.Host); e == nil {
		return nil, ErrDestinationDenied
	}
	if op.Method() != http.MethodGet && op.Method() != http.MethodPost {
		return nil, ErrUpstream
	}
	if len(body) > 2<<20 || (op.Method() == http.MethodGet && (len(body) > 0 || credential != "" || op.Stream())) || strings.ContainsAny(credential, "\r\n\x00") {
		return nil, ErrUpstream
	}
	overall := t.opts.OverallTimeout
	if overall == 0 {
		overall = 30 * time.Second
		if op.Method() == http.MethodPost {
			overall = 180 * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(parent, overall)
	owned := false
	defer func() {
		if !owned {
			cancel()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, safeError(err, err)
	}
	dnsCtx, dnsCancel := context.WithTimeout(ctx, t.opts.DNSTimeout)
	ips, err := t.opts.Resolver.LookupNetIP(dnsCtx, "ip", u.Host)
	dnsErr := dnsCtx.Err()
	dnsCancel()
	if err != nil {
		return nil, safeError(dnsErr, err)
	}
	if len(ips) == 0 {
		return nil, ErrDestinationDenied
	}
	ips = append([]netip.Addr(nil), ips...)
	for i, a := range ips {
		a = a.Unmap()
		if !allowedAddress(a, t.opts.DeniedCIDRs) {
			return nil, ErrDestinationDenied
		}
		ips[i] = a
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Compare(ips[j]) < 0 })
	if err := ctx.Err(); err != nil {
		return nil, safeError(err, err)
	}
	connectCtx, connectCancel := context.WithTimeout(ctx, t.opts.ConnectTimeout)
	conn, err := t.opts.DialContext(connectCtx, "tcp", net.JoinHostPort(ips[0].String(), "443"))
	connectErr := connectCtx.Err()
	connectCancel()
	if err != nil {
		return nil, safeError(connectErr, err)
	}
	if conn == nil {
		return nil, ErrUpstream
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	cleanup := func() { stop(); cancel(); conn.Close() }
	defer func() {
		if !owned {
			cleanup()
		}
	}()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Host, RootCAs: t.opts.TLSRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	tlsCtx, tlsCancel := context.WithTimeout(ctx, t.opts.TLSTimeout)
	err = tlsConn.HandshakeContext(tlsCtx)
	tlsErr := tlsCtx.Err()
	tlsCancel()
	if err != nil {
		return nil, safeError(tlsErr, err)
	}
	if p := tlsConn.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
		return nil, ErrUpstream
	}
	if err := ctx.Err(); err != nil {
		return nil, safeError(err, err)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method(), op.URL(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrUpstream
	}
	req.Close = true
	req.Header.Set("User-Agent", "harness-gateway/1")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "text/plain, text/html, application/json")
	if op.Method() == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if op.Stream() {
			req.Header.Set("Accept", "text/event-stream")
		}
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
	}
	// No http.Client/Transport: their reconnect, proxy, and reuse machinery cannot
	// accidentally create a second request. Write/read use this one TLS socket.
	tlsConn.SetDeadline(deadline(ctx, t.opts.HeaderTimeout))
	if err = req.Write(tlsConn); err != nil {
		return nil, safeError(ctx.Err(), err)
	}
	r := bufio.NewReaderSize(tlsConn, 4096)
	header, err := readHeader(r)
	if err != nil {
		return nil, safeError(ctx.Err(), err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(header), r)), req)
	if err != nil {
		return nil, safeError(ctx.Err(), err)
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 || resp.StatusCode < 200 || resp.StatusCode >= 300 || !validResponse(resp, op) {
		return nil, ErrUpstream
	}
	tlsConn.SetWriteDeadline(time.Time{})
	resp.Body = &responseBody{body: resp.Body, conn: tlsConn, ctx: ctx, idle: t.opts.IdleTimeout, cleanup: cleanup}
	owned = true
	return resp, nil
}

func safeError(ctxErr, errorValue error) error {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return ErrDeadline
	}
	var n net.Error
	if errors.As(errorValue, &n) && n.Timeout() {
		return ErrDeadline
	}
	return ErrUpstream
}

func deadline(ctx context.Context, phase time.Duration) time.Time {
	d := time.Now().Add(phase)
	if end, ok := ctx.Deadline(); ok && end.Before(d) {
		return end
	}
	return d
}

type responseBody struct {
	body    io.ReadCloser
	conn    net.Conn
	ctx     context.Context
	idle    time.Duration
	cleanup func()
	once    sync.Once
}

func (b *responseBody) Read(p []byte) (int, error) {
	if b.ctx.Err() != nil {
		b.Close()
		return 0, safeError(b.ctx.Err(), b.ctx.Err())
	}
	b.conn.SetReadDeadline(deadline(b.ctx, b.idle))
	n, err := b.body.Read(p)
	if err != nil {
		b.Close()
		if err != io.EOF {
			err = safeError(b.ctx.Err(), err)
		}
	}
	return n, err
}
func (b *responseBody) Close() error {
	// Close socket first: net/http body.Close can drain a response, which must
	// never delay cancellation or consume unlimited bytes during cleanup.
	b.once.Do(b.cleanup)
	return nil
}

func readHeader(r *bufio.Reader) ([]byte, error) {
	var b []byte
	var cl, te int
	var fields int
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		if len(b)+len(line) > 16<<10 || !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, ErrUpstream
		}
		if len(b) > 0 && len(line) > 2 {
			fields++
			if fields > 64 {
				return nil, ErrUpstream
			}
			if line[0] == ' ' || line[0] == '\t' {
				return nil, ErrUpstream
			}
			name, _, ok := bytes.Cut(line, []byte(":"))
			if !ok {
				return nil, ErrUpstream
			}
			switch strings.ToLower(string(name)) {
			case "content-length":
				cl++
			case "transfer-encoding":
				te++
			}
			if cl > 1 || te > 1 || (cl > 0 && te > 0) {
				return nil, ErrUpstream
			}
		}
		b = append(b, line...)
		if len(line) == 2 {
			return b, nil
		}
	}
}

func validResponse(r *http.Response, op Operation) bool {
	if len(r.Header.Values("Content-Encoding")) > 1 {
		return false
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return false
	}
	if len(r.TransferEncoding) > 1 || (len(r.TransferEncoding) == 1 && r.TransferEncoding[0] != "chunked") {
		return false
	}
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	if len(r.Header.Values("Content-Type")) != 1 {
		return false
	}
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	for k, v := range params {
		if k != "charset" || (strings.ToLower(v) != "utf-8" && strings.ToLower(v) != "us-ascii") {
			return false
		}
	}
	if op.Method() == http.MethodGet {
		return ct == "text/plain" || ct == "text/html" || ct == "application/json"
	}
	if op.Stream() {
		return ct == "text/event-stream"
	}
	return ct == "application/json"
}
