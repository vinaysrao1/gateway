//go:build linux

package isolation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type platformJail struct {
	c                       Config
	dir, work, temp, cgroup string
	groupFD, seccomp        *os.File
}

func prepare(c Config) (_ *Jail, err error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnsupported
	}
	if err = c.Limits.Validate(); err != nil {
		return nil, err
	}
	if len(c.Command) == 0 || !filepath.IsAbs(c.Command[0]) || c.Port < 1024 || c.Port > 65535 {
		return nil, errors.New("invalid sandbox command or bridge port")
	}
	for _, p := range []string{c.RuntimeRoot, c.Workspace, c.SocketPath, c.CgroupRoot} {
		if !filepath.IsAbs(p) {
			return nil, errors.New("sandbox paths must be absolute")
		}
	}
	if _, err = exec.LookPath("bwrap"); err != nil {
		return nil, ErrUnsupported
	}
	if err = runtimeTree(c.RuntimeRoot); err != nil {
		return nil, fmt.Errorf("invalid runtime: %w", err)
	}
	if err = ordinaryTree(c.Workspace); err != nil {
		return nil, fmt.Errorf("invalid workspace: %w", err)
	}
	if fi, e := os.Stat(c.SocketPath); e != nil || fi.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("broker socket missing")
	}
	for _, p := range []string{"gateway", "proc", "dev", "tmp", "home", "workspace", "run"} {
		if _, e := os.Stat(filepath.Join(c.RuntimeRoot, p)); e != nil {
			return nil, fmt.Errorf("runtime lacks %s", p)
		}
	}
	j := &platformJail{c: c}
	defer func() {
		if err != nil {
			_ = j.close()
		}
	}()
	j.dir, err = os.MkdirTemp("", "gateway-jail-")
	if err != nil {
		return nil, err
	}
	j.work = filepath.Join(j.dir, "workspace")
	j.temp = filepath.Join(j.dir, "temporary")
	for _, p := range []string{j.work, j.temp} {
		if err = os.Mkdir(p, 0700); err != nil {
			return nil, err
		}
	}
	if err = syscall.Mount("gateway-workspace", j.work, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, fmt.Sprintf("size=%d,nr_inodes=65536,mode=0755", c.Limits.WorkspaceBytes)); err != nil {
		return nil, ErrUnsupported
	}
	if err = syscall.Mount("gateway-temporary", j.temp, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, fmt.Sprintf("size=%d,nr_inodes=16384,mode=0777", c.Limits.TempBytes)); err != nil {
		return nil, ErrUnsupported
	}
	if err = copyTree(c.Workspace, j.work); err != nil {
		return nil, err
	}
	if err = os.Mkdir(filepath.Join(j.temp, "home"), 0700); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Join(j.temp, "home/.pi/agent"), 0700); err != nil {
		return nil, err
	}
	controllers, e := os.ReadFile(filepath.Join(c.CgroupRoot, "cgroup.controllers"))
	if e != nil {
		return nil, ErrUnsupported
	}
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !containsField(string(controllers), name) {
			return nil, ErrUnsupported
		}
	}
	if err = os.WriteFile(filepath.Join(c.CgroupRoot, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0600); err != nil {
		return nil, ErrUnsupported
	}
	j.cgroup = filepath.Join(c.CgroupRoot, filepath.Base(j.dir))
	if err = os.Mkdir(j.cgroup, 0700); err != nil {
		return nil, ErrUnsupported
	}
	for name, value := range map[string]string{"memory.max": strconv.FormatInt(c.Limits.SandboxMemoryBytes, 10), "memory.swap.max": "0", "memory.oom.group": "1", "pids.max": strconv.FormatInt(c.Limits.SandboxProcesses, 10), "cpu.max": fmt.Sprintf("%d 100000", c.Limits.SandboxCPUCores*100000)} {
		if err = os.WriteFile(filepath.Join(j.cgroup, name), []byte(value), 0600); err != nil {
			return nil, ErrUnsupported
		}
	}
	if _, err = os.Stat(filepath.Join(j.cgroup, "cgroup.kill")); err != nil {
		return nil, ErrUnsupported
	}
	j.groupFD, err = os.Open(j.cgroup)
	if err != nil {
		return nil, err
	}
	j.seccomp, err = os.CreateTemp(j.dir, "seccomp-")
	if err != nil {
		return nil, err
	}
	filter, e := seccompFilter(runtime.GOARCH)
	if e != nil {
		return nil, e
	}
	if _, err = j.seccomp.Write(filter); err != nil {
		return nil, err
	}
	if _, err = j.seccomp.Seek(0, 0); err != nil {
		return nil, err
	}
	return &Jail{impl: j}, nil
}

func containsField(s, name string) bool {
	for _, v := range strings.Fields(s) {
		if v == name {
			return true
		}
	}
	return false
}

func (j *platformJail) command(in, out *os.File) (*exec.Cmd, error) {
	for _, stream := range []any{j.c.Stdin, j.c.Stdout, j.c.Stderr} {
		if f, ok := stream.(*os.File); ok && f != nil {
			var st syscall.Stat_t
			if e := syscall.Fstat(int(f.Fd()), &st); e != nil || st.Mode&syscall.S_IFMT == syscall.S_IFSOCK {
				return nil, errors.New("sandbox standard streams must not be sockets")
			}
		}
	}
	// Go and bwrap can inherit ambient descriptors whose CLOEXEC bit was unset
	// by an invoking program. Mark all of them atomically before exec; os/exec
	// deliberately duplicates only ExtraFiles back to descriptors 3, 4 and 5.
	// close_range(2) is syscall 436 on both reviewed Linux architectures.
	if runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		return nil, ErrUnsupported
	}
	if _, _, e := syscall.Syscall(436, 3, ^uintptr(0), 4); e != 0 {
		return nil, ErrUnsupported
	}
	// The only preserved channels are trusted bootstrap control pipes and BPF.
	args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--unshare-user", "--disable-userns", "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL", "--ro-bind", j.c.RuntimeRoot, "/", "--proc", "/proc", "--dev", "/dev", "--bind", j.work, "/workspace", "--bind", j.temp, "/tmp", "--bind", filepath.Join(j.temp, "home"), "/home/agent", "--ro-bind", j.c.SocketPath, "/run/gateway.sock", "--clearenv", "--setenv", "HOME", "/home/agent", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "PI_CODING_AGENT_DIR", "/home/agent/.pi/agent", "--setenv", "NO_PROXY", "*", "--setenv", "TERM", "dumb", "--chdir", "/workspace", "--seccomp", "5"}
	if fi, e := os.Stat(filepath.Join(j.c.RuntimeRoot, "pi-config")); e == nil && fi.IsDir() {
		for _, name := range []string{"models.json", "settings.json"} {
			if fi, e := os.Stat(filepath.Join(j.c.RuntimeRoot, "pi-config", name)); e != nil || !fi.Mode().IsRegular() {
				return nil, errors.New("immutable Pi configuration missing")
			}
			placeholder := filepath.Join(j.temp, "home/.pi/agent", name)
			if e := os.WriteFile(placeholder, nil, 0600); e != nil {
				return nil, e
			}
			args = append(args, "--ro-bind", filepath.Join(j.c.RuntimeRoot, "pi-config", name), "/home/agent/.pi/agent/"+name)
		}
	}
	args = append(args, "/gateway", "bootstrap", "--port", strconv.Itoa(j.c.Port), "--fds", strconv.FormatInt(j.c.Limits.SandboxFDs, 10), "--")
	args = append(args, j.c.Command...)
	cmd := exec.Command("bwrap", args...)
	cmd.ExtraFiles = []*os.File{in, out, j.seccomp}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(j.groupFD.Fd()), Pdeathsig: syscall.SIGKILL}
	cmd.Stdin = j.c.Stdin
	cmd.Stdout = j.c.Stdout
	cmd.Stderr = j.c.Stderr
	return cmd, nil
}

func (j *platformJail) kill() error {
	if j.cgroup == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(j.cgroup, "cgroup.kill"), []byte("1"), 0600); err != nil {
		return err
	}
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		b, e := os.ReadFile(filepath.Join(j.cgroup, "cgroup.events"))
		if e != nil {
			return e
		}
		if strings.Contains(string(b), "populated 0") {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("sandbox process tree exceeded termination deadline")
}
func (j *platformJail) close() error {
	var errs []error
	if j.cgroup != "" {
		if e := j.kill(); e != nil && !os.IsNotExist(e) {
			errs = append(errs, e)
		}
		if j.groupFD != nil {
			_ = j.groupFD.Close()
		}
		if e := os.Remove(j.cgroup); e != nil && !os.IsNotExist(e) {
			errs = append(errs, e)
		}
	}
	if j.seccomp != nil {
		_ = j.seccomp.Close()
	}
	for _, p := range []string{j.work, j.temp} {
		if p != "" {
			if e := syscall.Unmount(p, 0); e != nil && e != syscall.EINVAL && e != syscall.ENOENT {
				errs = append(errs, e)
			}
		}
	}
	if j.dir != "" {
		if e := os.RemoveAll(j.dir); e != nil {
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
}
func (j *platformJail) export() error {
	// Stop membership is verified before trusting any exported filesystem data.
	b, err := os.ReadFile(filepath.Join(j.cgroup, "cgroup.events"))
	if err != nil || !strings.Contains(string(b), "populated 0") {
		return errors.New("sandbox tree still active")
	}
	return copyTree(j.work, j.c.Workspace)
}

func ordinaryTree(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("root must be an ordinary directory")
	}
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return errors.New("special files and symlinks are not permitted")
		}
		return nil
	})
}

func runtimeTree(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("runtime root must be an ordinary directory")
	}
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && !d.Type().IsRegular() && d.Type()&os.ModeSymlink == 0 {
			return errors.New("runtime contains special files")
		}
		return nil
	})
}

func copyTree(source, dest string) error {
	r, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer r.Close()
	output, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer output.Close()
	return fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if e = output.Mkdir(p, 0755); e != nil && !os.IsExist(e) {
				return e
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("workspace contains a special file or symlink")
		}
		in, e := r.Open(p)
		if e != nil {
			return e
		}
		defer in.Close()
		info, e := in.Stat()
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("workspace source changed")
		}
		// O_NOFOLLOW also protects export into an operator workspace containing a
		// previously produced symlink. No writes can follow a final-component link.
		out, e := output.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, info.Mode().Perm()&0777)
		if e != nil {
			return e
		}
		_, e = io.Copy(out, in)
		closeErr := out.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})
}

// A small deny-list profile prevents changing or joining namespaces, mount
// manipulation, ptrace, BPF and kernel control. Network isolation remains the
// primary mediation boundary. Unknown architectures are refused.
func seccompFilter(arch string) ([]byte, error) {
	var audit uint32
	var denied []uint32
	var clone uint32
	var socket, socketpair uint32
	switch arch {
	case "arm64":
		audit = 0xc00000b7
		clone = 220
		socket, socketpair = 198, 199
		denied = []uint32{39, 40, 41, 97, 104, 105, 117, 219, 268, 272, 273, 280, 282, 294, 425, 426, 427, 435, 442}
	case "amd64":
		audit = 0xc000003e
		clone = 56
		socket, socketpair = 41, 53
		denied = []uint32{101, 155, 165, 166, 169, 172, 175, 176, 248, 249, 250, 272, 298, 304, 308, 313, 321, 323, 425, 426, 427, 435, 442}
	default:
		return nil, ErrUnsupported
	}
	type insn struct {
		Code   uint16
		JT, JF uint8
		K      uint32
	}
	const load = 0x20
	const equal = 0x15
	const ret = 0x06
	const and = 0x54
	// x32 shares AUDIT_ARCH_X86_64 but changes syscall numbers. Reject that ABI
	// instead of allowing its numbers to miss the reviewed syscall rules.
	f := []insn{{load, 0, 0, 4}, {equal, 1, 0, audit}, {ret, 0, 0, 0x80000000}, {load, 0, 0, 0}, {0x35, 0, 1, 0x40000000}, {ret, 0, 0, 0x80000000}}
	for _, n := range denied {
		errno := uint32(1)
		if n == 435 {
			errno = 38
		}
		f = append(f, insn{equal, 0, 1, n}, insn{ret, 0, 0, 0x00050000 | errno})
	}
	// Alternative network families such as AF_VSOCK are not necessarily scoped
	// by an IP network namespace. Permit only the reviewed local/IP families.
	for _, rule := range []struct {
		nr       uint32
		families []uint32
	}{{socket, []uint32{1, 2, 10, 16}}, {socketpair, []uint32{1}}} {
		f = append(f, insn{equal, 0, uint8(len(rule.families)*2 + 2), rule.nr}, insn{load, 0, 0, 16})
		for _, family := range rule.families {
			f = append(f, insn{equal, 0, 1, family}, insn{ret, 0, 0, 0x7fff0000})
		}
		f = append(f, insn{ret, 0, 0, 0x00050001})
	}
	// clone permits ordinary processes/threads but no CLONE_NEW* flag.
	f = append(f, insn{equal, 0, 4, clone}, insn{load, 0, 0, 16}, insn{and, 0, 0, 0x7e020000}, insn{equal, 1, 0, 0}, insn{ret, 0, 0, 0x00050001}, insn{ret, 0, 0, 0x7fff0000})
	b := make([]byte, len(f)*8)
	for i, v := range f {
		binary.LittleEndian.PutUint16(b[i*8:], v.Code)
		b[i*8+2] = v.JT
		b[i*8+3] = v.JF
		binary.LittleEndian.PutUint32(b[i*8+4:], v.K)
	}
	return b, nil
}
