// Package isolation owns the NET-001, NET-002, RES-001 and LIFE-001 Linux boundary.
// Unsupported platforms and unavailable kernel controls fail closed.
package isolation

import (
	"errors"
	"github.com/vinaysrao1/gateway/internal/policy"
	"io"
	"os"
	"os/exec"
)

var ErrUnsupported = errors.New("enforced isolation requires Linux with bubblewrap, cgroup v2 delegation and mount privilege")

type Config struct {
	RuntimeRoot    string
	Workspace      string
	SocketPath     string
	CgroupRoot     string
	Port           int
	Limits         policy.Limits
	Command        []string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Jail owns all resource mounts and a process-tree cgroup. Close revokes the
// complete tree, including grandchildren, before releasing its mounts.
type Jail struct{ impl *platformJail }

func Prepare(c Config) (*Jail, error) { return prepare(c) }
func (j *Jail) Command(controlIn, controlOut *os.File) (*exec.Cmd, error) {
	return j.impl.command(controlIn, controlOut)
}
func (j *Jail) Kill() error  { return j.impl.kill() }
func (j *Jail) Close() error { return j.impl.close() }

// Export copies ordinary workspace data back after the process tree has ended.
func (j *Jail) Export() error { return j.impl.export() }
