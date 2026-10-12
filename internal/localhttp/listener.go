// Package localhttp bounds local HTTP connections and rejects ambiguous framing.
package localhttp

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

func Bound(l net.Listener, maxConnections, headerBytes, headerCount int, timeout time.Duration) net.Listener {
	return &boundedListener{Listener: l, slots: make(chan struct{}, maxConnections), headerMax: headerBytes, headerCount: headerCount, timeout: timeout}
}

type boundedListener struct {
	net.Listener
	slots                  chan struct{}
	headerMax, headerCount int
	timeout                time.Duration
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &framedConn{Conn: c, reader: bufio.NewReaderSize(c, l.headerMax+4), owner: l}, nil
		default:
			c.Close()
		}
	}
}

type framedConn struct {
	net.Conn
	reader  *bufio.Reader
	owner   *boundedListener
	once    sync.Once
	checked bool
	pending []byte
}

func (c *framedConn) Close() error { c.once.Do(func() { <-c.owner.slots }); return c.Conn.Close() }
func (c *framedConn) Read(p []byte) (int, error) {
	if !c.checked {
		c.checked = true
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.owner.timeout))
		var header bytes.Buffer
		for {
			line, e := c.reader.ReadSlice('\n')
			if e != nil || !bytes.HasSuffix(line, []byte("\r\n")) {
				return 0, errors.New("invalid headers")
			}
			header.Write(line)
			if header.Len() > c.owner.headerMax {
				return 0, errors.New("headers too large")
			}
			if bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}
		lines := strings.Split(header.String(), "\r\n")
		if len(lines)-3 > c.owner.headerCount {
			return 0, errors.New("too many headers")
		}
		var cl, te int
		for _, line := range lines[1:] {
			if line == "" {
				continue
			}
			if line[0] == ' ' || line[0] == '\t' {
				return 0, errors.New("folded header")
			}
			name, _, ok := strings.Cut(line, ":")
			if !ok {
				return 0, errors.New("invalid header")
			}
			switch strings.ToLower(name) {
			case "content-length":
				cl++
			case "transfer-encoding":
				te++
			}
		}
		if cl > 1 || te > 1 || cl > 0 && te > 0 {
			return 0, errors.New("ambiguous framing")
		}
		c.pending = header.Bytes()
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.reader.Read(p)
}
