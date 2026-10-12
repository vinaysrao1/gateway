// Package broker mediates per-run capabilities. It never trusts claimed tool identity.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vinaysrao1/gateway/internal/audit"
	"github.com/vinaysrao1/gateway/internal/policy"
	"github.com/vinaysrao1/gateway/internal/protocol"
	"github.com/vinaysrao1/gateway/internal/transport"
)

type Upstream interface {
	Do(context.Context, transport.Operation) (*http.Response, error)
}
type Options struct {
	Policy   *policy.Policy
	Upstream Upstream
	Audit    audit.Sink
	Secrets  map[string]string
}
type Server struct {
	policy                                       *policy.Policy
	upstream                                     Upstream
	audit                                        audit.Sink
	secrets                                      map[string]string
	runID                                        string
	ctx                                          context.Context
	cancel                                       context.CancelFunc
	mu                                           sync.Mutex
	active, closed                               bool
	inFlight, total, requestBytes, responseBytes int64
	parsingBytes                                 int64
	timer                                        *time.Timer
}

func New(o Options) (*Server, error) {
	if o.Policy == nil || o.Upstream == nil || o.Audit == nil {
		return nil, errors.New("invalid broker configuration")
	}
	secrets := make(map[string]string)
	for k, v := range o.Secrets {
		secrets[k] = v
	}
	if m, ok := o.Policy.Model(); ok {
		v := secrets[m.CredentialRef]
		if v == "" || strings.ContainsAny(v, "\r\n\x00") {
			return nil, errors.New("credential unavailable")
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, errors.New("identity unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{policy: o.Policy, upstream: o.Upstream, audit: o.Audit, secrets: secrets, runID: hex.EncodeToString(id[:]), ctx: ctx, cancel: cancel}, nil
}
func (s *Server) Activate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active {
		return errors.New("invalid run state")
	}
	s.active = true
	s.timer = time.AfterFunc(time.Duration(s.policy.Limits().RunSeconds)*time.Second, s.Close)
	return nil
}
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.active = false
	s.cancel()
	if s.timer != nil {
		s.timer.Stop()
	}
}
func (s *Server) isActive() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.active && !s.closed }
func (s *Server) record(e audit.Event) bool {
	e.RunID = s.runID
	e.PolicyDigest = s.policy.Digest()
	if s.audit.Record(e) != nil {
		s.Close()
		return false
	}
	return true
}
func (s *Server) admit(id, capability, method string, n int64) (int, string) {
	l := s.policy.Limits()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.closed {
		return 503, "run_unavailable"
	}
	if s.inFlight >= l.ConcurrentOperations || s.total >= l.TotalOperations || n > l.TotalRequestBytes-s.requestBytes {
		return 429, "budget_exceeded"
	}
	e := audit.Event{Kind: "admit", RunID: s.runID, PolicyDigest: s.policy.Digest(), RequestID: id, Capability: capability, Method: method, RequestBytes: n}
	if s.audit.Record(e) != nil {
		s.closed = true
		s.active = false
		s.cancel()
		return 503, "run_unavailable"
	}
	s.inFlight++
	s.total++
	s.requestBytes += n
	return 0, ""
}
func (s *Server) chargeResponse(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if n > s.policy.Limits().TotalResponseBytes-s.responseBytes {
		s.responseBytes = s.policy.Limits().TotalResponseBytes
		return false
	}
	s.responseBytes += n
	return true
}
func errorReply(w http.ResponseWriter, status int, code, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}, "request_id": id})
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rid [16]byte
	if _, err := rand.Read(rid[:]); err != nil {
		errorReply(w, 503, "run_unavailable", "")
		return
	}
	id := hex.EncodeToString(rid[:])
	deny := func(status int, code string) {
		if !s.record(audit.Event{Kind: "deny", RequestID: id, Method: safeMethod(r.Method), Outcome: code}) {
			status = 503
			code = "run_unavailable"
		}
		errorReply(w, status, code, id)
	}
	l := s.policy.Limits()
	if r.URL.IsAbs() || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "%\\") || r.Method == "CONNECT" {
		deny(400, "invalid_request")
		return
	}
	if enc := r.Header.Get("Content-Encoding"); len(r.Header.Values("Content-Encoding")) > 1 || enc != "" && enc != "identity" {
		deny(400, "invalid_request")
		return
	}
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-gateway-") {
			deny(400, "invalid_request")
			return
		}
	}
	if r.Header.Get("Upgrade") != "" {
		deny(400, "invalid_request")
		return
	}
	if r.URL.Path == "/healthz" {
		if r.Method != "GET" {
			deny(405, "method_not_allowed")
			return
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			deny(400, "invalid_request")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ready": true, "active": s.isActive()})
		return
	}
	if !s.isActive() {
		deny(503, "run_unavailable")
		return
	}
	var op transport.Operation
	var normalizedBody []byte
	var modelStream bool
	var credentialRef string
	var capID string
	var maximum int64
	var duration int64
	switch {
	case r.URL.Path == "/v1/chat/completions":
		m, ok := s.policy.Model()
		if !ok {
			deny(404, "route_not_found")
			return
		}
		if r.Method != "POST" {
			deny(405, "method_not_allowed")
			return
		}
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || ct != "application/json" {
			deny(400, "invalid_request")
			return
		}
		if r.ContentLength > l.RequestBytes {
			deny(413, "request_too_large")
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(time.Duration(l.ReadBodySeconds) * time.Second))
		reservation := 4 * (l.RequestBytes + 1024)
		if !s.reserveParsing(reservation) {
			deny(429, "budget_exceeded")
			return
		}
		defer s.releaseParsing(reservation)
		body, err := io.ReadAll(io.LimitReader(r.Body, l.RequestBytes+1))
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
		if err != nil {
			deny(400, "invalid_request")
			return
		}
		if int64(len(body)) > l.RequestBytes {
			deny(413, "request_too_large")
			return
		}
		body, stream, err := protocol.ValidateModel(body, m)
		if err != nil {
			status, code := 400, "invalid_request"
			if errors.Is(err, protocol.ErrModelDenied) {
				status = 403
				code = "capability_denied"
			}
			deny(status, code)
			return
		}
		normalizedBody = body
		modelStream = stream
		credentialRef = m.CredentialRef
		capID = m.ID
		maximum = l.ModelResponseBytes
		duration = l.ModelSeconds
	case strings.HasPrefix(r.URL.Path, "/gateway/v1/fetch/"):
		if r.Method != "GET" {
			deny(405, "method_not_allowed")
			return
		}
		resource, ok := s.policy.Fetch(strings.TrimPrefix(r.URL.Path, "/gateway/v1/fetch/"))
		if !ok {
			deny(403, "capability_denied")
			return
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			deny(400, "invalid_request")
			return
		}

		capID = resource.ID
		maximum = l.FetchResponseBytes
		duration = l.FetchSeconds
	default:
		deny(404, "route_not_found")
		return
	}
	// Admission precedes target DNS, TCP and credential use (POL-001/AUDIT-001).
	if status, code := s.admit(id, capID, r.Method, int64(len(normalizedBody))); status != 0 {
		deny(status, code)
		return
	}
	start := time.Now()
	outcome := "upstream_failed"
	var bytes, received int64
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
		s.record(audit.Event{Kind: "terminal", RequestID: id, Capability: capID, Method: safeMethod(r.Method), Outcome: outcome, RequestBytes: int64(len(normalizedBody)), ResponseBytes: bytes, ReceivedBytes: received, DurationMS: time.Since(start).Milliseconds()})
	}()
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(duration)*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	var opErr error
	if r.Method == "POST" {
		op, opErr = s.policy.AuthorizeModel(normalizedBody, s.secrets[credentialRef], modelStream)
	} else {
		op, opErr = s.policy.AuthorizeFetch(capID)
	}
	if opErr != nil {
		outcome = "capability_denied"
		errorReply(w, 403, outcome, id)
		return
	}
	resp, err := s.upstream.Do(ctx, op)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			outcome = "cancelled"
			panic(http.ErrAbortHandler)
		}
		status, code := 502, "upstream_failed"
		if errors.Is(err, transport.ErrDestinationDenied) {
			status = 403
			code = "capability_denied"
		}
		if ctx.Err() != nil || errors.Is(err, transport.ErrDeadline) {
			status = 504
			code = "deadline_exceeded"
		}
		outcome = code
		errorReply(w, status, code, id)
		return
	}
	defer resp.Body.Close()
	ct, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	allowed := !op.Stream() && ct == "application/json" || op.Method() == "GET" && (ct == "text/plain" || ct == "text/html") || op.Stream() && ct == "text/event-stream"
	if charset, ok := params["charset"]; len(params) > 0 && (!ok || len(params) != 1 || !strings.EqualFold(charset, "utf-8") && !strings.EqualFold(charset, "us-ascii")) {
		allowed = false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || err != nil || !allowed || resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {
		errorReply(w, 502, "upstream_failed", id)
		return
	}
	if resp.ContentLength > maximum {
		outcome = "response_too_large"
		errorReply(w, 502, "upstream_failed", id)
		return
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("X-Request-Id", id)
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, int(l.CopyBufferBytes))
	var completion protocol.Completion
	var terminalTail []byte
	send := func(p []byte) bool {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(l.WriteSeconds) * time.Second))
		n, err := w.Write(p)
		bytes += int64(n)
		if err != nil || n != len(p) {
			outcome = "client_disconnected"
			return false
		}
		if op.Stream() {
			if http.NewResponseController(w).Flush() != nil {
				outcome = "client_disconnected"
				return false
			}
		}
		return true
	}
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			received += int64(n)
			charged := s.chargeResponse(int64(n))
			if received > maximum || !charged {
				outcome = "response_too_large"
				panic(http.ErrAbortHandler)
			}
			if op.Stream() {
				if completion.Feed(buf[:n]) != nil {
					outcome = "upstream_incomplete"
					panic(http.ErrAbortHandler)
				}
			}
			// Never let the SDK observe a complete terminal event until the upstream
			// HTTP framing is verified. Earlier partial marker bytes are harmless:
			// the completing event boundary stays here until clean EOF.
			if op.Stream() && completion.TerminalSeen() {
				if len(terminalTail)+n > protocol.MaxSSEEventBytes {
					outcome = "upstream_incomplete"
					panic(http.ErrAbortHandler)
				}
				terminalTail = append(terminalTail, buf[:n]...)
			} else if !send(buf[:n]) {
				return
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				if op.Stream() && !completion.Finished() {
					outcome = "upstream_incomplete"
					panic(http.ErrAbortHandler)
				}
				if len(terminalTail) > 0 && !send(terminalTail) {
					return
				}
				outcome = "complete"
				return
			}
			if ctx.Err() != nil {
				outcome = "cancelled"
			} else {
				outcome = "upstream_incomplete"
			}
			panic(http.ErrAbortHandler)
		}
	}

}

func safeMethod(m string) string {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT":
		return m
	default:
		return "OTHER"
	}
}
func (s *Server) reserveParsing(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || n > s.policy.Limits().RequestBufferBytes-s.parsingBytes {
		return false
	}
	s.parsingBytes += n
	return true
}
func (s *Server) releaseParsing(n int64) { s.mu.Lock(); s.parsingBytes -= n; s.mu.Unlock() }
