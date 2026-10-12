// Package supervisor owns fail-closed run activation and whole-tree cleanup.
package supervisor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vinaysrao1/gateway/internal/isolation"
)

type Config = isolation.Config

// Run implements PREPARING -> ACTIVE -> STOPPING -> CLOSED. The bootstrap has
// only health access until its bounded READY handshake proves the OS controls.
// Agent execution begins only after activate succeeds; revoke is idempotent.
func Run(ctx context.Context, c Config, activate func() error, revoke func()) (err error) {
	if activate == nil || revoke == nil {
		return errors.New("missing lifecycle callbacks")
	}
	defer revoke()
	j, err := isolation.Prepare(c)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, j.Close()) }()
	childIn, parentOut, err := os.Pipe()
	if err != nil {
		return err
	}
	defer childIn.Close()
	defer parentOut.Close()
	parentIn, childOut, err := os.Pipe()
	if err != nil {
		return err
	}
	defer parentIn.Close()
	defer childOut.Close()
	cmd, err := j.Command(childIn, childOut)
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return errors.New("sandbox startup failed")
	}
	_ = childIn.Close()
	_ = childOut.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ready := make(chan string, 1)
	go func() {
		r := bufio.NewReaderSize(io.LimitReader(parentIn, 64), 64)
		line, e := r.ReadString('\n')
		if e != nil || len(line) > 63 {
			ready <- ""
			return
		}
		ready <- line
	}()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	defer func() { revoke(); _ = parentOut.Close() }()
	stop := func(reason error) error {
		revoke()
		killErr := j.Kill()
		select {
		case <-done:
			return errors.Join(reason, killErr)
		case <-time.After(2 * time.Second):
			return errors.Join(reason, killErr, errors.New("sandbox process wait exceeded deadline"))
		}
	}
	select {
	case line := <-ready:
		if line != "READY\n" {
			return stop(errors.New("sandbox readiness failed"))
		}
	case <-timer.C:
		return stop(errors.New("sandbox readiness timeout"))
	case <-ctx.Done():
		return stop(ctx.Err())
	case e := <-done:
		return fmt.Errorf("sandbox exited before ready: %w", e)
	}
	if err = activate(); err != nil {
		return stop(err)
	}
	if _, err = parentOut.Write([]byte("ACTIVE\n")); err != nil {
		return stop(errors.New("sandbox activation failed"))
	}
	select {
	case err = <-done:
		revoke()
		if killErr := j.Kill(); killErr != nil {
			return errors.Join(err, killErr)
		}
		if err == nil {
			err = j.Export()
		}
		return err
	case <-ctx.Done():
		return stop(ctx.Err())
	}
}
