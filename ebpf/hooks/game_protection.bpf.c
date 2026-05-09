#include "vmlinux.h"

#include <errno.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ebpf_types.h"

const volatile __u64 TARGET_CGROUP = 0;

static __always_inline __u32 current_tgid(void) {
  return (__u32) (bpf_get_current_pid_tgid() >> 32);
}

static __always_inline int is_target_cgroup(__u64 cgid) {
  return TARGET_CGROUP != 0 && cgid == TARGET_CGROUP;
}

static __always_inline __u64 task_cgroup_id(struct task_struct* task) {
  struct css_set*     css;
  struct cgroup*      cgrp;
  struct kernfs_node* kn;

  if (!task) return 0;

  css = BPF_CORE_READ(task, cgroups);
  if (!css) return 0;

  cgrp = BPF_CORE_READ(css, dfl_cgrp);
  if (!cgrp) return 0;

  kn = BPF_CORE_READ(cgrp, kn);
  if (!kn) return 0;

  return BPF_CORE_READ(kn, id);
}

/*
 * Blocks ptrace/proc-memory style access to tasks inside TARGET_CGROUP.
 *
 * This protects all current and future PIDs moved into TARGET_CGROUP.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(restrict_ptrace_access, struct task_struct* child, unsigned int mode, int ret) {
  __u64 current_cgid;
  __u32 current_pid;
  __u64 target_cgid;
  __u32 target_pid;

  if (ret) return ret;

  if (TARGET_CGROUP == 0 || !child) return 0;

  current_cgid = bpf_get_current_cgroup_id();
  current_pid  = current_tgid();

  target_cgid = task_cgroup_id(child);
  if (!is_target_cgroup(target_cgid)) return 0;

  target_pid = BPF_CORE_READ(child, tgid);

  /*
   * Allow to inspect itself.
   */
  if (current_pid == target_pid) return 0;

  bpf_printk("Denied %s: current_pid=%u current_cgid=%llu "
             "target_pid=%u target_cgid=%llu protected_cgid=%llu mode=%d\n",
             "ptrace_access_check", current_pid, current_cgid, target_pid, target_cgid,
             TARGET_CGROUP, mode);

  return -EPERM;
}

/*
 * Blocks a protected task from being traced.
 *
 * In this hook, the protected task is the current task.
 * The parent argument is the would be the tracer.
 */
SEC("lsm/ptrace_traceme")
int BPF_PROG(restrict_ptrace_traceme, struct task_struct* parent, int ret) {
  __u64 current_cgid;
  __u32 current_pid;
  __u64 parent_cgid;
  __u32 parent_pid;

  if (ret) return ret;

  if (TARGET_CGROUP == 0) return 0;

  current_cgid = bpf_get_current_cgroup_id();
  if (!is_target_cgroup(current_cgid)) return 0;
  current_pid = current_tgid();

  parent_cgid = parent ? task_cgroup_id(parent) : 0;
  parent_pid  = parent ? BPF_CORE_READ(parent, tgid) : 0;

  bpf_printk("Denied %s: current_pid=%u current_cgid=%llu "
             "target_pid=%u target_cgid=%llu protected_cgid=%llu",
             "ptrace_access_check", current_pid, current_cgid, parent_pid, parent_cgid,
             TARGET_CGROUP);
  return -EPERM;
}

char _license[] SEC("license") = "GPL";