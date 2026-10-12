package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/json"
	"errors"
	"github.com/vinaysrao1/gateway/internal/policy"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(c context.Context, n, h string) ([]netip.Addr, error) {
	return f(c, n, h)
}

func fixture(t *testing.T, h http.HandlerFunc) (Options, *httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream.example"}, DNSNames: []string{"upstream.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"http/1.1"}}
	s.StartTLS()
	t.Cleanup(s.Close)
	dns, dials := new(atomic.Int32), new(atomic.Int32)
	o := Options{TLSRoots: roots, Resolver: resolverFunc(func(ctx context.Context, n, h string) ([]netip.Addr, error) {
		dns.Add(1)
		if n != "ip" || h != "upstream.example" {
			t.Errorf("unexpected lookup %s %s", n, h)
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}), DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		dials.Add(1)
		if n != "tcp" || a != "8.8.8.8:443" {
			t.Errorf("unpinned dial %s %s", n, a)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
	}}
	return o, s, dns, dials
}
func newTransport(t *testing.T, o Options) *Transport {
	t.Helper()
	tr, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// DST-002 and HTTP-001: hostname verification and authority use policy hostname;
// literal TCP destination is the normalized, deterministic checked answer.
func TestPinnedTLSAndReconstructedRequest(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	const body = `{"max_tokens":1,"messages":[],"model":"fixture","stream":false}`
	var seen atomic.Int32
	o, _, dns, dials := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		b, _ := io.ReadAll(r.Body)
		if r.Host != "upstream.example" || r.TLS.ServerName != "upstream.example" || r.Proto != "HTTP/1.1" || r.Header.Get("Authorization") != "Bearer canary" || r.Header.Get("Accept-Encoding") != "identity" || string(b) != body {
			t.Errorf("wrong request authority/bytes")
		}
		if !r.Close || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("unsafe request headers")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "{\"ok\":true}")
	})
	o.Resolver = resolverFunc(func(c context.Context, n, h string) ([]netip.Addr, error) {
		dns.Add(1)
		return []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("::ffff:8.8.8.8")}, nil
	})
	tr := newTransport(t, o)
	for i := 0; i < 2; i++ {
		r, err := tr.Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/api", Method: "POST", Credential: "canary", Body: []byte(body)}))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || string(b) != "{\"ok\":true}" {
			t.Fatalf("wrong response %q %v", b, err)
		}
	}
	if dns.Load() != 2 || dials.Load() != 2 || seen.Load() != 2 {
		t.Fatalf("pool, repeated DNS or replay: %d %d %d", dns.Load(), dials.Load(), seen.Load())
	}
}

func TestAddressCorpus(t *testing.T) {
	deny := []string{"0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0", "100.127.255.255", "127.0.0.1", "169.254.169.254", "172.16.0.0", "172.31.255.255", "192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1", "198.18.0.0", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.0", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "100:0:0:1::1", "2001::1", "2001:1::3", "2001:1ff:ffff::1", "2001:db8::1", "2002:808:808::1", "2620:4f:8000::1", "3fff::1", "3fff:fff:ffff::1", "5f00::1", "fc00::1", "fdff:ffff::1", "fe80::1", "ff02::1"}
	for _, v := range deny {
		t.Run(v, func(t *testing.T) {
			if allowedAddress(netip.MustParseAddr(v), nil) {
				t.Fatal("special address allowed")
			}
		})
	}
	for _, v := range []string{"1.1.1.1", "8.8.8.8", "::ffff:8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "198.17.255.255", "198.20.0.0", "2001:4860:4860::8888", "2606:4700:4700::1111", "3ffe::1"} {
		if !allowedAddress(netip.MustParseAddr(v), nil) {
			t.Errorf("ordinary public address denied %s", v)
		}
	}
	if allowedAddress(netip.MustParseAddr("8.8.8.8"), []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}) {
		t.Fatal("operator internal CIDR ignored")
	}
}

func TestDeniedResolutionNeverDials(t *testing.T) {
	for _, answers := range [][]string{nil, {"10.0.0.1"}, {"8.8.8.8", "127.0.0.1"}, {"::ffff:169.254.169.254"}, {"2002:7f00:1::1"}} {
		var dns, dials atomic.Int32
		tr := newTransport(t, Options{Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			dns.Add(1)
			var a []netip.Addr
			for _, s := range answers {
				a = append(a, netip.MustParseAddr(s))
			}
			return a, nil
		}), DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected")
		}})
		_, err := tr.Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "GET"}))
		if !errors.Is(err, ErrDestinationDenied) || dns.Load() != 1 || dials.Load() != 0 {
			t.Fatalf("denial emitted dial: %v %d %d", err, dns.Load(), dials.Load())
		}
	}
}

// A rebinding resolver's second answer must never be consulted.
func TestDialFailureHasNoAddressFallback(t *testing.T) {
	var dns, dials atomic.Int32
	tr := newTransport(t, Options{Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if dns.Add(1) > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")}, nil
	}), DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("secret remote detail")
	}})
	_, err := tr.Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "GET"}))
	if err != ErrUpstream || dns.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("fallback/retry %v %d %d", err, dns.Load(), dials.Load())
	}
}

func TestTLSHostnameAndUntrustedRootFail(t *testing.T) {
	for _, wrongHost := range []bool{true, false} {
		o, _, _, dials := fixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unverified TLS sent HTTP request") })
		uri := "https://upstream.example/"
		if wrongHost {
			uri = "https://wrong.example/"
			o.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			})
		} else {
			o.TLSRoots = x509.NewCertPool()
		}
		_, err := newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: uri, Method: "POST", Credential: "canary", Body: []byte("{}")}))
		if err != ErrUpstream || dials.Load() != 1 {
			t.Fatalf("TLS identity accepted %v %d", err, dials.Load())
		}
	}
}

func TestRedirectAndCompressedResponsesFailWithoutReplay(t *testing.T) {
	for _, status := range []int{301, 307, 401, 500, 200} {
		o, _, _, dials := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", "https://127.0.0.1/private")
			if status == 200 {
				w.Header().Set("Content-Encoding", "gzip")
			}
			w.WriteHeader(status)
			io.WriteString(w, "canary secret raw upstream error")
		})
		_, err := newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "POST", Credential: "canary"}))
		if err != ErrUpstream || dials.Load() != 1 {
			t.Fatalf("response replay/leak %v %d", err, dials.Load())
		}
	}
}

func TestDisconnectAfterReceivedBodyDoesNotReplay(t *testing.T) {
	var received atomic.Int32
	o, _, dns, dials := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		received.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	})
	_, err := newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "POST"}))
	if err != ErrUpstream || received.Load() != 1 || dials.Load() != 1 || dns.Load() != 1 {
		t.Fatalf("replayed failed request: %v received=%d dials=%d DNS=%d", err, received.Load(), dials.Load(), dns.Load())
	}
}

func TestDuplicateEncodingAndUnsupportedMediaFail(t *testing.T) {
	for _, ct := range []string{"application/octet-stream", "application/json; charset=utf-16", "application/json; x=1", "application/json"} {
		o, _, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			if ct == "application/json" {
				w.Header().Add("Content-Encoding", "identity")
				w.Header().Add("Content-Encoding", "gzip")
			}
			io.WriteString(w, "{}")
		})
		_, err := newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "POST"}))
		if err != ErrUpstream {
			t.Errorf("unsupported response accepted %s: %v", ct, err)
		}
	}
}

// Every range in the pinned registry remains denied, including its boundaries.
// Mapped IPv6 is normalized before classification, rather than blindly denied.
func TestPinnedIANASnapshots(t *testing.T) {
	for _, file := range []string{"testdata/iana-ipv4-special-2025-10-09.csv", "testdata/iana-ipv6-special-2025-10-09.csv"} {
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(f).ReadAll()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows[1:] {
			for _, block := range strings.Split(row[0], ",") {
				p, err := netip.ParsePrefix(strings.Fields(block)[0])
				if err != nil {
					t.Fatal(err)
				}
				start := p.Masked().Addr()
				last := start.As16()
				bits := p.Bits()
				if start.Is4() {
					bits += 96
				}
				for bit := bits; bit < 128; bit++ {
					last[bit/8] |= 1 << uint(7-bit%8)
				}
				end := netip.AddrFrom16(last)
				if start.Is4() {
					end = end.Unmap()
				}
				for _, addr := range []netip.Addr{start, end} {
					if allowedAddress(addr, nil) {
						t.Errorf("IANA boundary allowed: %s (%s)", addr, p)
					}
				}
			}
		}
	}
}

func TestCancellationAndIdleCloseUpstream(t *testing.T) {
	for _, cancelExplicit := range []bool{true, false} {
		closed := make(chan struct{})
		o, _, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(closed)
		})
		o.IdleTimeout = 30 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		r, err := newTransport(t, o).Do(ctx, testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "POST", Stream: true}))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if cancelExplicit {
			cancel()
		}
		_, err = r.Body.Read(make([]byte, 10))
		r.Body.Close()
		cancel()
		if err == nil || err == io.EOF {
			t.Fatalf("stall/cancellation marked complete: %v", err)
		}
		if !cancelExplicit && err != ErrDeadline {
			t.Fatalf("wrong idle error %v", err)
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("upstream remained open after cancellation")
		}
	}
}

func TestStreamBytesAndTruncation(t *testing.T) {
	const events = "data: one\n\ndata: two\n\ndata: [DONE]\n\n"
	o, _, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, events)
	})
	r, err := newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "POST", Stream: true}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil || string(b) != events {
		t.Fatalf("stream mutated %q %v", b, err)
	}
	o, _, _, _ = fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "999")
		io.WriteString(w, "data: partial\n\n")
	})
	r, err = newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "POST", Stream: true}))
	if err != nil {
		t.Fatal(err)
	}
	b, err = io.ReadAll(r.Body)
	r.Body.Close()
	if err == nil || strings.Contains(string(b), "[DONE]") {
		t.Fatalf("truncation synthesized success %q %v", b, err)
	}
}

func TestDNSAndResponseHeaderDeadlines(t *testing.T) {
	tr := newTransport(t, Options{DNSTimeout: 10 * time.Millisecond, Resolver: resolverFunc(func(c context.Context, _, _ string) ([]netip.Addr, error) { <-c.Done(); return nil, c.Err() }), DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("DNS timeout dialed")
		return nil, nil
	}})
	_, err := tr.Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "GET"}))
	if err != ErrDeadline {
		t.Fatal(err)
	}
	o, _, _, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	o.HeaderTimeout = 20 * time.Millisecond
	_, err = newTransport(t, o).Do(context.Background(), testOperation(t, fixtureOp{URL: "https://upstream.example/", Method: "GET"}))
	if err != ErrDeadline {
		t.Fatal(err)
	}
}

func TestInvalidOperationsNoDNS(t *testing.T) {
	tr := newTransport(t, Options{Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("zero-authority operation resolved")
		return nil, nil
	})})
	if _, err := tr.Do(context.Background(), Operation{}); err != ErrDestinationDenied {
		t.Fatalf("zero-authority operation accepted: %v", err)
	}
}

func TestResponseFraming(t *testing.T) {
	for _, raw := range []string{"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n", "HTTP/1.1 200 OK\nContent-Length: 0\n\n", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("x", 17000) + "\r\n\r\n"} {
		if _, err := readHeader(bufio.NewReader(strings.NewReader(raw))); err == nil {
			t.Error("ambiguous framing accepted")
		}
	}
}

type fixtureOp struct {
	URL, Method, Credential string
	Body                    []byte
	Stream                  bool
}

func testOperation(t *testing.T, v fixtureOp) Operation {
	t.Helper()
	wire := map[string]any{"schema_version": 1, "limits": policy.DefaultLimits(), "denied_cidrs": []string{}, "model_routes": []any{}, "fetch_resources": []any{}}
	if v.Method == "POST" {
		wire["model_routes"] = []any{policy.ModelRoute{ID: "model", LocalPath: "/v1/chat/completions", UpstreamURL: v.URL, Protocol: "openai-chat-v1", AllowedModels: []string{"fixture"}, CredentialRef: "key", MaxOutputTokens: 1}}
	} else {
		wire["fetch_resources"] = []any{policy.FetchResource{ID: "fetch", URL: v.URL}}
	}
	encoded, _ := json.Marshal(wire)
	p, err := policy.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if v.Method == "POST" {
		if len(v.Body) == 0 {
			v.Body = []byte(`{"model":"fixture","max_tokens":1}`)
		}
		var m map[string]json.RawMessage
		json.Unmarshal(v.Body, &m)
		if m == nil {
			m = map[string]json.RawMessage{}
		}
		if _, ok := m["model"]; !ok {
			m["model"] = json.RawMessage(`"fixture"`)
		}
		if _, ok := m["max_tokens"]; !ok {
			m["max_tokens"] = json.RawMessage(`1`)
		}
		m["stream"], _ = json.Marshal(v.Stream)
		v.Body, _ = json.Marshal(m)
		if v.Credential == "" {
			v.Credential = "fixture-key"
		}
		op, e := p.AuthorizeModel(v.Body, v.Credential, v.Stream)
		if e != nil {
			t.Fatal(e)
		}
		return op
	}
	op, err := p.AuthorizeFetch("fetch")
	if err != nil {
		t.Fatal(err)
	}
	return op
}
