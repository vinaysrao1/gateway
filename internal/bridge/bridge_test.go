package bridge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBridgeRejectsBeforeNormalization(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "gateway-bridge-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "g.sock")
	ul, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int64
	us := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "approved")
	})}
	go us.Serve(ul)
	defer us.Close()
	reserve, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := reserve.Addr().String()
	reserve.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, socket, addr) }()
	until := time.Now().Add(time.Second)
	for {
		c, e := net.Dial("tcp", addr)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(until) {
			t.Fatal("bridge did not start")
		}
		time.Sleep(time.Millisecond)
	}
	for _, raw := range []string{"GET http://evil.test/gateway/v1/fetch/approved HTTP/1.1\r\nHost: local\r\n\r\n", "GET /gateway/v1/fetch/approved HTTP/1.1\r\nHost: local\r\nConnection: X-Gateway-Run\r\nX-Gateway-Run: another\r\n\r\n", "GET /gateway/v1/fetch/approved HTTP/1.1\r\nHost: local\r\nConnection: Content-Encoding\r\nContent-Encoding: gzip\r\n\r\n"} {
		c, e := net.Dial("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(c, raw)
		res, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		c.Close()
		if res.StatusCode != 400 {
			t.Fatal(res.StatusCode)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("normalized denied request reached broker")
	}
	res, e := http.Get("http://" + addr + "/gateway/v1/fetch/approved")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil || string(b) != "approved" || calls.Load() != 1 {
		t.Fatal(e, string(b), calls.Load())
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge stop blocked")
	}
}
func TestNoExternalBridgeListener(t *testing.T) {
	if e := Run(context.Background(), "/no.sock", "0.0.0.0:8787"); e == nil || !strings.Contains(e.Error(), "loopback") {
		t.Fatal(e)
	}
}
