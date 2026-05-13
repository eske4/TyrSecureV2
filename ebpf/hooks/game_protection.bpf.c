#include "vmlinux.h"
#include "sys/mman.h"

#include <errno.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ebpf_types.h"

const volatile __u64 TARGET_CGROUP = 0;
const volatile __u32 DAEMON_PID = 0;

/* Memory Permission Definitions */


#ifndef VM_WRITE
#define VM_WRITE 0x00000002UL
#endif

#ifndef VM_EXEC
#define VM_EXEC 0x00000004UL
#endif

/* Process and Cgroup Functions */

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

static __always_inline int has_write(unsigned long prot) { return (prot & PROT_WRITE) != 0; }

static __always_inline int has_exec(unsigned long prot) { return (prot & PROT_EXEC) != 0; }

static __always_inline int has_wx(unsigned long prot) {
  return (prot & PROT_WRITE) && (prot & PROT_EXEC);
}

/* ptrace_access_check
 *
 * Blocks ptrace/proc-memory access to processes inside TARGET_CGROUP.
 *
 * Protects:
 * - all current and future processes moved into TARGET_CGROUP.
 * - allows a protected process to inspect itself.
 * - denies ptrace access from other processes.
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

  if (current_pid == target_pid) return 0;

  bpf_printk("Denied ptrace access: current_pid=%u current_cgid=%llu "
             "target_pid=%u target_cgid=%llu protected_cgid=%llu mode=%d\n",
             current_pid, current_cgid, target_pid, target_cgid, TARGET_CGROUP, mode);

  return -EPERM;
}

/* lsm/ptrace_traceme
 *
 * Blocks PTRACE_TRACEME for processes inside TARGET_CGROUP.
 *
 * This prevents a protected process from asking its parent to trace it.
 * The request is denied regardless of whether the parent is inside or outside the protected cgroup.
 *
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

  bpf_printk("Denied ptrace_traceme: current_pid=%u current_cgid=%llu "
             "parent_pid=%u parent_cgid=%llu protected_cgid=%llu\n",
             current_pid, current_cgid, parent_pid, parent_cgid, TARGET_CGROUP);
  return -EPERM;
}

/* mmap_file
 *
 * Prevents executable-memory mappings in TARGET_CGROUP.
 *
 * Blocks:
 * - direct W+X(writable,executable) mappings, both anonymous and file-backed
 * - anonymous memory mappings RX(readable,executable) - not backed by file on disk
 */

SEC("lsm/mmap_file")
int BPF_PROG(restrict_mmap_file, struct file* file, unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret) {
  __u64 current_cgid;
  __u32 current_pid;

  if (ret) return ret;

  if (TARGET_CGROUP == 0) return 0;

  current_cgid = bpf_get_current_cgroup_id();
  if (!is_target_cgroup(current_cgid)) return 0;

  current_pid = current_tgid();

  if (has_wx(reqprot) || has_wx(prot)) {
    bpf_printk("Denied memory mappings: pid=%u cgid=%llu protected_cgid=%llu reason=wx reqprot=%lu "
               "prot=%lu flags=%lu\n",
               current_pid, current_cgid, TARGET_CGROUP, reqprot, prot, flags);
    return -EPERM;
  }

  if (!file && (has_exec(reqprot) || has_exec(prot))) {
    bpf_printk("Denied memory mappings: pid=%u cgid=%llu protected_cgid=%llu reason=anonymous_exec "
               "reqprot=%lu prot=%lu flags=%lu\n",
               current_pid, current_cgid, TARGET_CGROUP, reqprot, prot, flags);
    return -EPERM;
  }

  return 0;
}

/* file_mprotect
 *
 * Prevents changes in memory permission flags inside TARGET_CGROUP.
 *
 * Blocks:
 * - memory from becoming both writable and executable (W+X).
 * - anonymous memory becoming executable (X).
 * - writable VMA becoming executable (X).
 */

SEC("lsm/file_mprotect")
int BPF_PROG(restrict_file_mprotect, struct vm_area_struct* vma, unsigned long reqprot,
             unsigned long prot, int ret) {
  __u64         current_cgid;
  __u32         current_pid;
  struct file*  backing_file;
  unsigned long vm_flags;

  if (ret) return ret;

  if (TARGET_CGROUP == 0 || !vma) return 0;

  current_cgid = bpf_get_current_cgroup_id();
  if (!is_target_cgroup(current_cgid)) return 0;

  current_pid = current_tgid();

  if (has_wx(reqprot) || has_wx(prot)) {
    bpf_printk("Denied memory permission change: pid=%u cgid=%llu protected_cgid=%llu reason=wx "
               "reqprot=%lu prot=%lu\n",
               current_pid, current_cgid, TARGET_CGROUP, reqprot, prot);
    return -EPERM;
  }

  backing_file = BPF_CORE_READ(vma, vm_file);
  vm_flags     = BPF_CORE_READ(vma, vm_flags);

  if ((vm_flags & VM_WRITE) && (has_exec(reqprot) || has_exec(prot))) {
    bpf_printk("Denied memory permission change: pid=%u cgid=%llu protected_cgid=%llu "
               "reason=writable_to_exec vm_flags=%lu reqprot=%lu prot=%lu\n",
               current_pid, current_cgid, TARGET_CGROUP, vm_flags, reqprot, prot);
    return -EPERM;
  }

  if (!backing_file && (has_exec(reqprot) || has_exec(prot))) {
    bpf_printk("Denied memory permission change: pid=%u cgid=%llu protected_cgid=%llu "
               "reason=anonymous_exec reqprot=%lu prot=%lu\n",
               current_pid, current_cgid, TARGET_CGROUP, reqprot, prot);
    return -EPERM;
  }

  return 0;
}

/* lsm/inode_permission */

SEC("lsm/inode_permission")
int BPF_PROG(check_inode_write, struct inode* inode, int mask, int ret) {
  struct task_struct* task;
  task = (struct task_struct*) bpf_get_current_task();

  __u64 cg_id = task_cgroup_id(task);

  __u32 current_pid = current_tgid();

  if(current_pid == DAEMON_PID) return 0;

  if (!is_target_cgroup(cg_id)) return 0;

  bpf_printk("Deny write: task in cgroup %llu PID: %llu DAEMON SAVED PID: %llu\n",cg_id, current_pid, DAEMON_PID);
  return -EPERM;

  return 0;
}

char _license[] SEC("license") = "GPL";
