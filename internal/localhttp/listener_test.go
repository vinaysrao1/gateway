package localhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRejectAmbiguousOrMixedLineFraming(t *testing.T) {
	for _, raw := range []string{"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 0\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "GET / HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"} {
		t.Run(raw[:4], func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			calls := make(chan struct{}, 1)
			s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls <- struct{}{}; w.WriteHeader(200) })}
			go s.Serve(Bound(l, 2, 1024, 16, time.Second))
			defer s.Close()
			c, e := net.Dial("tcp", l.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			io.WriteString(c, raw)
			b, _ := io.ReadAll(c)
			select {
			case <-calls:
				t.Fatal("handler saw ambiguous input")
			default:
			}
			if strings.Contains(string(b), "200 OK") {
				t.Fatal(string(b))
			}
		})
	}
}
func TestBoundConnections(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	b := Bound(l, 1, 1024, 16, time.Second)
	defer b.Close()
	client, _ := net.Dial("tcp", l.Addr().String())
	defer client.Close()
	accepted, e := b.Accept()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	extra, _ := net.Dial("tcp", l.Addr().String())
	defer extra.Close()
	done := make(chan struct{})
	go func() {
		c, _ := b.Accept()
		if c != nil {
			c.Close()
		}
		close(done)
	}()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if _, e = extra.Read(one); e == nil {
		t.Fatal("excess connection not closed")
	}
	accepted.Close()
	b.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("listener stuck")
	}
}
