// NET-001 / NET-002: run only inside the actual isolated namespace.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
  struct rlimit files;
  assert(getrlimit(RLIMIT_NOFILE, &files) == 0);
  assert(files.rlim_cur == 256 && files.rlim_max == 256);
  assert(socket(AF_INET, SOCK_RAW, 1) == -1 && errno == EPERM);
  assert(socket(AF_PACKET, SOCK_RAW, 0) == -1 && errno == EPERM);
  assert(socket(AF_VSOCK, SOCK_STREAM, 0) == -1 && errno == EPERM);
  assert(syscall(425, 1, NULL) == -1 && errno == EPERM); // io_uring_setup
  assert(unshare(CLONE_NEWNET) == -1 && errno == EPERM);
  assert(syscall(SYS_setns, -1, CLONE_NEWNET) == -1 && errno == EPERM);
  assert(mount("none", "/tmp", "tmpfs", 0, NULL) == -1 && errno == EPERM);
  puts("RAW_AND_NAMESPACE_ESCAPE_BLOCKED");
  return 0;
}
