//go:build linux

package isolation

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Security outcomes for the profile, independent of its filter layout.
func TestSeccompPrivilegesAndNormalProcesses(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		b, err := seccompFilter(arch)
		if err != nil {
			t.Fatal(err)
		}
		audit, clone, mount, socket := uint32(0xc00000b7), uint32(220), uint32(40), uint32(198)
		if arch == "amd64" {
			audit = 0xc000003e
			clone = 56
			mount = 165
			socket = 41
		}
		cases := []struct {
			arch, nr uint32
			args     uint32
			result   uint32
		}{
			{audit, clone, 17, 0x7fff0000},
			{audit, clone, 0x40000000, 0x00050001},
			{audit, mount, 0, 0x00050001},
			{audit, 435, 0, 0x00050026},
			{audit, socket, 1, 0x7fff0000},
			{audit, socket, 2, 0x7fff0000},
			{audit, socket, 10, 0x7fff0000},
			{audit, socket, 40, 0x00050001},
			{audit, 425, 0, 0x00050001},
			{audit, 426, 0, 0x00050001},
			{audit, 427, 0, 0x00050001},
			{audit ^ 1, 1, 0, 0x80000000},
			{audit, mount | 0x40000000, 0, 0x80000000},
		}
		for _, c := range cases {
			if got := runFilter(t, b, c.arch, c.nr, c.args); got != c.result {
				t.Fatalf("%s syscall%d: got%x want%x", arch, c.nr, got, c.result)
			}
		}
	}
	if _, err := seccompFilter("riscv64"); err == nil {
		t.Fatal("unreviewed architecture allowed")
	}
}
func runFilter(t *testing.T, b []byte, arch, nr, args uint32) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(b)/8; pc++ {
		v := b[pc*8:]
		code := binary.LittleEndian.Uint16(v)
		k := binary.LittleEndian.Uint32(v[4:])
		switch code {
		case 0x20:
			switch k {
			case 0:
				a = nr
			case 4:
				a = arch
			case 16:
				a = args
			default:
				t.Fatal("invalid load")
			}
		case 0x15:
			if a == k {
				pc += int(v[2])
			} else {
				pc += int(v[3])
			}
		case 0x54:
			a &= k
		case 0x35:
			if a >= k {
				pc += int(v[2])
			} else {
				pc += int(v[3])
			}
		case 0x06:
			return k
		default:
			t.Fatal("invalid opcode")
		}
	}
	t.Fatal("unterminated filter")
	return 0
}

func TestWorkspaceRejectsDeputyAndSymlink(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("unix", filepath.Join(dir, "host.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if ordinaryTree(dir) == nil {
		t.Fatal("socket-bearing workspace accepted")
	}
	if err = os.Remove(filepath.Join(dir, "host.sock")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc", filepath.Join(dir, "outside")); err != nil {
		t.Fatal(err)
	}
	if ordinaryTree(dir) == nil {
		t.Fatal("symlink workspace accepted")
	}
}

func TestExportCannotFollowIntermediateSymlink(t *testing.T) {
	source, destination, outside := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested/file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(destination, "nested")); err != nil {
		t.Fatal(err)
	}
	if copyTree(source, destination) == nil {
		t.Fatal("export followed directory symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatal("export wrote outside root")
	}
}
