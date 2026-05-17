#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "ebpf_types.h"

// This is the actual memory allocation (16MB in this case)
// A dummy program that exists just to make the ELF valid.
// You will LOAD this, but you will NEVER attach it.

const volatile __u32 DAEMON_PID = 0;

SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_to_self, int cmd, union bpf_attr* attr, unsigned int size) {
  __u32 current_pid = bpf_get_current_pid_tgid() >> 32;

  if (current_pid != DAEMON_PID) { return -EPERM; }

  return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_proc, struct task_struct* child, unsigned int mode) {
  __u32 current_pid = BPF_CORE_READ(child, tgid);

  if (current_pid == DAEMON_PID) { return -EPERM; }

  return 0;
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_me, struct task_struct* parent) {
  __u32 current_pid = bpf_get_current_pid_tgid() >> 32;

  // Block the daemon itself from entering "trace me" mode
  if (current_pid == DAEMON_PID) { return -EPERM; }
  return 0;
}

char _license[] SEC("license") = "GPL";
