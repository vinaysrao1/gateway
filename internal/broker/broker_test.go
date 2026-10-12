package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vinaysrao1/gateway/internal/audit"
	"github.com/vinaysrao1/gateway/internal/policy"
	"github.com/vinaysrao1/gateway/internal/transport"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type upstreamFunc func(context.Context, transport.Operation) (*http.Response, error)

func (f upstreamFunc) Do(c context.Context, o transport.Operation) (*http.Response, error) {
	return f(c, o)
}

type sink struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
}

func (a *sink) Record(e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("private secret failure")
	}
	a.events = append(a.events, e)
	return nil
}
func testPolicy(t *testing.T, change func(*policy.Limits)) *policy.Policy {
	t.Helper()
	l := policy.DefaultLimits()
	if change != nil {
		change(&l)
	}
	b, e := json.Marshal(map[string]any{"schema_version": 1, "limits": l, "model_routes": []policy.ModelRoute{{ID: "model", LocalPath: "/v1/chat/completions", UpstreamURL: "https://model.gateway.test/v1/chat/completions", Protocol: "openai-chat-v1", AllowedModels: []string{"gateway-test"}, CredentialRef: "model-key", MaxOutputTokens: 128}}, "fetch_resources": []policy.FetchResource{{ID: "approved", URL: "https://docs.gateway.test/approved"}}, "denied_cidrs": []string{}})
	if e != nil {
		t.Fatal(e)
	}
	p, e := policy.Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func testServer(t *testing.T, p *policy.Policy, u Upstream, a audit.Sink) *Server {
	t.Helper()
	s, e := New(Options{Policy: p, Upstream: u, Audit: a, Secrets: map[string]string{"model-key": "canary-secret"}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Activate(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func response(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}
func TestDenyHasNoUpstreamEffect(t *testing.T) {
	calls := 0
	a := &sink{}
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) {
		calls++
		return response(`{}`), nil
	}), a)
	for _, tc := range []struct {
		method, path, body string
		headers            map[string]string
		status             int
	}{{"GET", "/unknown", "", nil, 404}, {"GET", "/gateway/v1/fetch/private", "", nil, 403}, {"GET", "/gateway/v1/fetch/approved?url=https://evil.test", "", nil, 400}, {"GET", "/gateway/v1/fetch/approved", "", map[string]string{"X-Gateway-Run": "other"}, 400}, {"POST", "/v1/chat/completions", `{"model":"gateway-test","messages":[{"role":"user","content":"hi"}],"fallback":"evil"}`, map[string]string{"Content-Type": "application/json"}, 400}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		for k, v := range tc.headers {
			r.Header.Set(k, v)
		}
		s.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s status %d body %s", tc.path, w.Code, w.Body)
		}
	}
	if calls != 0 {
		t.Fatal("denied operation reached upstream")
	}
}
func TestAuditBeforeUpstreamAndHeadersRebuilt(t *testing.T) {
	a := &sink{}
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(_ context.Context, o transport.Operation) (*http.Response, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if len(a.events) != 1 || a.events[0].Kind != "admit" {
			t.Fatal("no prior admission")
		}
		if o.URL() != "https://model.gateway.test/v1/chat/completions" || o.Credential() != "canary-secret" || bytes.Contains(o.Body(), []byte("canary-secret")) {
			t.Fatal("wrong authority")
		}
		return response(`{"ok":true}`), nil
	}), a)
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"gateway-test","messages":[{"role":"user","content":"hi"}]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer attacker")
	r.Host = "evil.test"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal(w.Code, w.Body)
	}
	if len(a.events) != 2 || a.events[1].Outcome != "complete" {
		t.Fatal(a.events)
	}
}
func TestAuditFailureAndRevocation(t *testing.T) {
	calls := 0
	a := &sink{fail: true}
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) {
		calls++
		return response(`{}`), nil
	}), a)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/gateway/v1/fetch/approved", nil))
	if w.Code != 503 || calls != 0 || s.isActive() {
		t.Fatal(w.Code, calls)
	}
	if strings.Contains(w.Body.String(), "private") {
		t.Fatal("leaked error")
	}
}
func TestConcurrencyAndCancellation(t *testing.T) {
	entered := make(chan struct{})
	closed := make(chan struct{})
	a := &sink{}
	s := testServer(t, testPolicy(t, func(l *policy.Limits) { l.ConcurrentOperations = 1 }), upstreamFunc(func(c context.Context, _ transport.Operation) (*http.Response, error) {
		close(entered)
		<-c.Done()
		close(closed)
		return nil, c.Err()
	}), a)
	ts := httptest.NewServer(s)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/gateway/v1/fetch/approved", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, _ := ts.Client().Do(r)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	<-entered
	resp, e := ts.Client().Get(ts.URL + "/gateway/v1/fetch/approved")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatal(resp.StatusCode)
	}
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("upstream not cancelled")
	}
	<-done
}
func TestFetchNoCredentialAndRedirectSanitized(t *testing.T) {
	a := &sink{}
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(_ context.Context, o transport.Operation) (*http.Response, error) {
		if o.Credential() != "" || len(o.Body()) > 0 {
			t.Fatal("fetch gained model credential")
		}
		resp := response("canary-secret")
		resp.StatusCode = 307
		resp.Header.Set("Location", "https://evil.test/")
		return resp, nil
	}), a)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/gateway/v1/fetch/approved", nil))
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret") || w.Header().Get("Location") != "" {
		t.Fatal(w.Code, w.Body)
	}
}
func TestResponseCapAbortsRatherThanSucceeds(t *testing.T) {
	s := testServer(t, testPolicy(t, func(l *policy.Limits) { l.FetchResponseBytes = 4 }), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) {
		r := response("0123456789")
		r.ContentLength = -1
		return r, nil
	}), &sink{})
	ts := httptest.NewServer(s)
	defer ts.Close()
	r, e := ts.Client().Get(ts.URL + "/gateway/v1/fetch/approved")
	if e == nil {
		defer r.Body.Close()
		_, e = io.ReadAll(r.Body)
	}
	if e == nil {
		t.Fatal("cap breach appeared successful")
	}
}
func TestPhaseDeadlineIs504(t *testing.T) {
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) { return nil, transport.ErrDeadline }), &sink{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/gateway/v1/fetch/approved", nil))
	if w.Code != 504 {
		t.Fatal(w.Code)
	}
}
func TestParsingReservationIsBounded(t *testing.T) {
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) { return response(`{}`), nil }), &sink{})
	max := s.policy.Limits().RequestBufferBytes
	if !s.reserveParsing(max) || s.reserveParsing(1) {
		t.Fatal("unbounded reservations")
	}
	s.releaseParsing(max)
	if !s.reserveParsing(1) {
		t.Fatal("reservation leaked")
	}
	s.releaseParsing(1)
}
func TestUntrustedAuditLabelsCannotExhaustSink(t *testing.T) {
	var out bytes.Buffer
	a, _ := audit.New(&out, 2048, 8192)
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) { return response(`{}`), nil }), a)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(strings.Repeat("X", 3000), "/unknown", nil))
	if w.Code != 404 || !s.isActive() {
		t.Fatal("unbounded method revoked authority", w.Code)
	}
	if bytes.Contains(out.Bytes(), []byte(strings.Repeat("X", 100))) {
		t.Fatal("untrusted label logged")
	}
}
func TestCleanHTTPIncompleteSSEIsNotComplete(t *testing.T) {
	a := &sink{}
	s := testServer(t, testPolicy(t, nil), upstreamFunc(func(context.Context, transport.Operation) (*http.Response, error) {
		resp := response("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	}), a)
	ts := httptest.NewServer(s)
	defer ts.Close()
	resp, e := ts.Client().Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gateway-test","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	if e == nil {
		defer resp.Body.Close()
		_, e = io.ReadAll(resp.Body)
	}
	if e == nil {
		t.Fatal("incomplete stream had successful HTTP termination")
	}
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		found := false
		for _, event := range a.events {
			if event.Kind == "terminal" {
				found = true
				if event.Outcome != "upstream_incomplete" {
					t.Fatal(event.Outcome)
				}
			}
		}
		a.mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing terminal audit")
		}
		time.Sleep(time.Millisecond)
	}
}
