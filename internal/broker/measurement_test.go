package broker

import (
	"context"
	"fmt"
	"github.com/vinaysrao1/gateway/internal/bridge"
	"github.com/vinaysrao1/gateway/internal/transport"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in measurement uses real loopback/Unix mediation and a deterministic
// in-memory upstream to isolate local overhead from DNS/TLS/remote latency.
func TestLocalMediationMeasurement(t *testing.T) {
	if os.Getenv("GATEWAY_MEASURE") != "1" {
		t.Skip("opt-in performance measurement")
	}
	const sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, sse)
			http.NewResponseController(w).Flush()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer direct.Close()
	sample := func(url string, concurrency, n int, stream bool) []float64 {
		client := &http.Client{Timeout: 2 * time.Second}
		jobs := make(chan int)
		durations := make([]float64, n)
		var wg sync.WaitGroup
		for range concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					start := time.Now()
					var r *http.Response
					var e error
					if stream {
						r, e = client.Post(url, "application/json", strings.NewReader(`{"model":"gateway-test","messages":[{"role":"user","content":"hi"}],"stream":true}`))
					} else {
						r, e = client.Get(url)
					}
					if e != nil {
						t.Error(e)
						continue
					}
					if stream {
						var one [1]byte
						_, e = io.ReadFull(r.Body, one[:])
						durations[i] = float64(time.Since(start).Microseconds()) / 1000
						if e != nil {
							t.Error(e)
						}
					}
					_, e = io.Copy(io.Discard, r.Body)
					r.Body.Close()
					if e != nil || r.StatusCode != 200 {
						t.Error("measurement failed", r.StatusCode, e)
					}
					if !stream {
						durations[i] = float64(time.Since(start).Microseconds()) / 1000
					}
				}
			}()
		}
		for i := range n {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		client.CloseIdleConnections()
		return durations
	}
	percentile := func(x []float64) float64 { sort.Float64s(x); return x[(len(x)*95)/100] }
	for _, mode := range []struct {
		concurrency int
		stream      bool
	}{{1, false}, {4, false}, {1, true}} {
		concurrency, stream := mode.concurrency, mode.stream
		baseline := sample(direct.URL, concurrency, 1200, stream)
		var mediated []float64
		for range 6 {
			dir, e := os.MkdirTemp("/tmp", "gateway-measure-")
			if e != nil {
				t.Fatal(e)
			}
			socket := filepath.Join(dir, "g.sock")
			ctx, cancel := context.WithCancel(context.Background())
			s := testServer(t, testPolicy(t, nil), upstreamFunc(func(_ context.Context, o transport.Operation) (*http.Response, error) {
				if o.Stream() {
					r := response(sse)
					r.Header.Set("Content-Type", "text/event-stream")
					return r, nil
				}
				return response(`{"ok":true}`), nil
			}), &sink{})
			serve := make(chan error, 1)
			go func() { serve <- s.Serve(ctx, socket) }()
			port, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			addr := port.Addr().String()
			port.Close()
			bridgeDone := make(chan error, 1)
			go func() { bridgeDone <- bridge.Run(ctx, socket, addr) }()
			deadline := time.Now().Add(time.Second)
			for {
				r, e := http.Get("http://" + addr + "/healthz")
				if e == nil {
					r.Body.Close()
					if r.StatusCode == 200 {
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("measurement readiness")
				}
				time.Sleep(time.Millisecond)
			}
			path := "/gateway/v1/fetch/approved"
			if stream {
				path = "/v1/chat/completions"
			}
			mediated = append(mediated, sample("http://"+addr+path, concurrency, 200, stream)...)
			cancel()
			<-bridgeDone
			<-serve
			s.Close()
			os.RemoveAll(dir)
		}
		p95 := percentile(mediated)
		base := percentile(baseline)
		t.Logf("MEASUREMENT stream_first_byte=%v concurrency=%d samples=%d direct_p95_ms=%.3f mediated_p95_ms=%.3f added_p95_ms=%.3f", stream, concurrency, len(mediated), base, p95, p95-base)
		if p95-base > 10 {
			t.Fatal(fmt.Sprintf("mediation target exceeded: %.3fms", p95-base))
		}
	}
}
