//go:build linux

package supervisor

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vinaysrao1/gateway/internal/bridge"
)

// Bootstrap is trusted setup code inside the jail. Its descriptors are closed
// before Pi starts; agent output is never parsed as host commands.
func Bootstrap(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	port := f.Int("port", 0, "")
	fds := f.Uint64("fds", 256, "")
	if err := f.Parse(args); err != nil {
		return err
	}
	command := f.Args()
	if len(command) == 0 || *port < 1024 || *port > 65535 || *fds < 3 || *fds > 256 {
		return errors.New("invalid bootstrap arguments")
	}
	control := os.NewFile(3, "activation")
	ready := os.NewFile(4, "readiness")
	if control == nil || ready == nil {
		return errors.New("missing bootstrap channels")
	}
	defer control.Close()
	defer ready.Close()
	if err := verify(); err != nil {
		return err
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: *fds, Max: *fds}); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bridgeDone := make(chan error, 1)
	address := "127.0.0.1:" + strconv.Itoa(*port)
	go func() { bridgeDone <- bridge.Run(ctx, "/run/gateway.sock", address) }()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, e := client.Get("http://" + address + "/healthz")
		if e == nil {
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-bridgeDone:
			return e
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("bridge readiness timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := ready.Write([]byte("READY\n")); err != nil {
		return errors.New("readiness failed")
	}
	_ = ready.Close()
	line, err := bufio.NewReaderSize(io.LimitReader(control, 64), 64).ReadString('\n')
	if err != nil || line != "ACTIVE\n" {
		return errors.New("activation failed")
	}
	_ = control.Close()
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = "/workspace"
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return errors.New("agent startup failed")
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- cmd.Wait() }()
	select {
	case err = <-agentDone:
		return err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-agentDone
		return ctx.Err()
	case <-bridgeDone:
		_ = cmd.Process.Kill()
		<-agentDone
		return errors.New("bridge failed")
	}
}

func verify() error {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		return errors.New("sandbox network isolation missing")
	}
	loopback := false
	for _, iface := range ifs {
		if iface.Name == "lo" && iface.Flags&net.FlagLoopback != 0 {
			loopback = true
			continue
		}
		addrs, e := iface.Addrs()
		if e != nil || iface.Flags&net.FlagUp != 0 || len(addrs) != 0 {
			return errors.New("sandbox has a usable external interface")
		}
	}
	if !loopback {
		return errors.New("sandbox loopback missing")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return errors.New("sandbox proc unavailable")
	}
	for key, value := range map[string]string{"CapEff": "0000000000000000", "CapPrm": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2"} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok && k == key && strings.TrimSpace(v) == value {
				found = true
			}
		}
		if !found {
			return errors.New("sandbox privilege restriction missing")
		}
	}
	if os.Getuid() != 65534 || os.Getgid() != 65534 {
		return errors.New("sandbox identity restriction missing")
	}
	return nil
}
