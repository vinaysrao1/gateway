// Package audit writes bounded metadata before external effects (AUDIT-001).
package audit

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

type Event struct {
	Kind          string    `json:"kind"`
	RequestID     string    `json:"request_id,omitempty"`
	RunID         string    `json:"run_id"`
	PolicyDigest  string    `json:"policy_digest"`
	Capability    string    `json:"capability,omitempty"`
	Method        string    `json:"method,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	RequestBytes  int64     `json:"request_bytes,omitempty"`
	ReceivedBytes int64     `json:"received_bytes,omitempty"`
	ResponseBytes int64     `json:"response_bytes,omitempty"`
	DurationMS    int64     `json:"duration_ms,omitempty"`
	Time          time.Time `json:"time"`
}

type Sink interface{ Record(Event) error }

type Log struct {
	mu                          sync.Mutex
	out                         io.Writer
	closer                      io.Closer
	recordMax, fileMax, written int64
	failed                      bool
}

func New(out io.Writer, recordMax, fileMax int64) (*Log, error) {
	if out == nil || recordMax < 256 || fileMax < recordMax {
		return nil, errors.New("invalid audit configuration")
	}
	return &Log{out: out, recordMax: recordMax, fileMax: fileMax}, nil
}

// Open requires a fresh path; it never appends to a prior run's audit file.
func Open(path string, recordMax, fileMax int64) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("cannot create audit")
	}
	l, err := New(f, recordMax, fileMax)
	if err != nil {
		f.Close()
		return nil, err
	}
	l.closer = f
	return l, nil
}
func (l *Log) Record(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed {
		return errors.New("audit unavailable")
	}
	e.Time = time.Now().UTC()
	b, err := json.Marshal(e)
	b = append(b, '\n')
	if err != nil || int64(len(b)) > l.recordMax || int64(len(b)) > l.fileMax-l.written {
		l.failed = true
		return errors.New("audit limit exceeded")
	}
	n, err := l.out.Write(b)
	l.written += int64(n)
	if err != nil || n != len(b) {
		l.failed = true
		return errors.New("audit write failed")
	}
	return nil
}
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed = true
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}
