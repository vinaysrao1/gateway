// Gateway is a harness-owned external access broker. Use run for enforced execution.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/vinaysrao1/gateway/internal/audit"
	"github.com/vinaysrao1/gateway/internal/bridge"
	"github.com/vinaysrao1/gateway/internal/broker"
	"github.com/vinaysrao1/gateway/internal/policy"
	"github.com/vinaysrao1/gateway/internal/supervisor"
	"github.com/vinaysrao1/gateway/internal/transport"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := dispatch(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}
func dispatch(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: gateway run|serve|bridge|bootstrap")
	}
	if args[0] == "bootstrap" {
		return supervisor.Bootstrap(ctx, args[1:])
	}
	if args[0] == "bridge" {
		f := flag.NewFlagSet("bridge", flag.ContinueOnError)
		socket := f.String("socket", "", "per-run Unix socket")
		listen := f.String("listen", "127.0.0.1:8787", "isolated loopback endpoint")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *socket == "" || f.NArg() != 0 {
			return errors.New("bridge requires socket")
		}
		return bridge.Run(ctx, *socket, *listen)
	}
	if args[0] != "serve" && args[0] != "run" {
		return errors.New("unknown command")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	policyPath := f.String("policy", "", "operator policy")
	secretPath := f.String("secrets", "", "host-only secret JSON map")
	socketPath := f.String("socket", "", "private socket path (serve only)")
	auditPath := f.String("audit", "", "fresh audit file")
	caPath := f.String("ca", "", "additional trusted CA PEM for approved upstream")
	runtimeRoot := f.String("runtime-root", "", "immutable Linux runtime root")
	workspace := f.String("workspace", "", "workspace copied into quota-backed jail")
	cgroupRoot := f.String("cgroup-root", "/sys/fs/cgroup", "delegated cgroup v2 root")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if *policyPath == "" || *secretPath == "" {
		return errors.New("policy and secrets are required")
	}
	data, e := readBounded(*policyPath, policy.MaxPolicyBytes)
	if e != nil {
		return errors.New("cannot load policy")
	}
	policyBytes := append([]byte(nil), data...)
	p, e := policy.Parse(data)
	if e != nil {
		return errors.New("invalid policy")
	}
	data, e = readBounded(*secretPath, 64<<10)
	if e != nil {
		return errors.New("cannot load secrets")
	}
	var secrets map[string]string
	if policy.DecodeStrict(data, 4, &secrets) != nil || secrets == nil {
		return errors.New("invalid secrets")
	}
	info, e := os.Lstat(*secretPath)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("secret file must be private regular file")
	}
	var roots *x509.CertPool
	if *caPath != "" {
		pem, e := readBounded(*caPath, 1<<20)
		if e != nil {
			return errors.New("cannot load CA")
		}
		roots, e = x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid CA")
		}
	}
	limits := p.Limits()
	tr, e := transport.New(transport.Options{TLSRoots: roots, DeniedCIDRs: p.DeniedCIDRs(), DNSTimeout: seconds(limits.DNSSeconds), ConnectTimeout: seconds(limits.ConnectSeconds), TLSTimeout: seconds(limits.TLSSeconds), HeaderTimeout: seconds(limits.ResponseHeaderSeconds), IdleTimeout: seconds(limits.StreamIdleSeconds)})
	if e != nil {
		return e
	}
	if args[0] == "serve" {
		if *socketPath == "" || *auditPath == "" || f.NArg() != 0 {
			return errors.New("serve requires socket and audit; it does not isolate agents")
		}
	}
	if args[0] == "run" {
		if *runtimeRoot == "" || *workspace == "" || f.NArg() == 0 || *socketPath != "" {
			return errors.New("run requires runtime-root, workspace and command; socket is supervisor-owned")
		}
		dir, e := os.MkdirTemp("", "gateway-run-")
		if e != nil {
			return errors.New("cannot create run directory")
		}
		defer os.RemoveAll(dir)
		*socketPath = filepath.Join(dir, "gateway.sock")
		if *auditPath == "" {
			return errors.New("run requires audit path")
		}
	}
	log, e := audit.Open(*auditPath, limits.AuditRecordBytes, limits.AuditFileBytes)
	if e != nil {
		return e
	}
	defer log.Close()
	snapshot, err := os.OpenFile(*auditPath+".policy.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create policy snapshot")
	}
	n, err := snapshot.Write(policyBytes)
	closeErr := snapshot.Close()
	if err != nil || n != len(policyBytes) || closeErr != nil {
		_ = os.Remove(*auditPath + ".policy.json")
		return errors.New("cannot save policy snapshot")
	}
	s, e := broker.New(broker.Options{Policy: p, Upstream: tr, Audit: log, Secrets: secrets})
	if e != nil {
		return e
	}
	defer s.Close()
	if args[0] == "serve" {
		if e = s.Activate(); e != nil {
			return e
		}
		return s.Serve(ctx, *socketPath)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(serveCtx, *socketPath) }()
	// Socket readiness is local setup; readiness does not activate egress.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
ready:
	for {
		select {
		case e := <-done:
			if e == nil {
				return errors.New("broker stopped before readiness")
			}
			return e
		case <-deadline.C:
			return errors.New("broker readiness timeout")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, e := os.Stat(*socketPath); e == nil {
				break ready
			}
		}
	}
	runCtx, stopRun := context.WithTimeout(ctx, seconds(limits.RunSeconds))
	defer stopRun()
	go func() {
		select {
		case <-done:
			stopRun()
		case <-runCtx.Done():
		}
	}()
	e = supervisor.Run(runCtx, supervisor.Config{RuntimeRoot: *runtimeRoot, Workspace: *workspace, SocketPath: *socketPath, CgroupRoot: *cgroupRoot, Limits: limits, Command: f.Args(), Port: 8787, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}, s.Activate, s.Close)
	return e
}
func readBounded(path string, n int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, n+1))
	if e != nil || int64(len(b)) > n {
		return nil, errors.New("file too large")
	}
	return b, nil
}
func seconds(n int64) time.Duration { return time.Duration(n) * time.Second }
