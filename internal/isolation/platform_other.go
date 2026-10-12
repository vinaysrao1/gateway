//go:build !linux

package isolation

import (
	"os"
	"os/exec"
)

type platformJail struct{}

func prepare(Config) (*Jail, error)                                 { return nil, ErrUnsupported }
func (*platformJail) command(*os.File, *os.File) (*exec.Cmd, error) { return nil, ErrUnsupported }
func (*platformJail) kill() error                                   { return ErrUnsupported }
func (*platformJail) close() error                                  { return nil }
func (*platformJail) export() error                                 { return ErrUnsupported }
