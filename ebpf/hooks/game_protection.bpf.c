#include "sys/mman.h"
#include "vmlinux.h"

#include <errno.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ebpf_types.h"

const volatile __u64 TARGET_CGROUP = 0;
const volatile __u32 DAEMON_PID    = 0;

#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef VM_WRITE
#define VM_WRITE 0x00000002UL
#endif

#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif

#ifndef MAY_APPEND
#define MAY_APPEND 0x00000008
#endif

#ifndef KERNFS_TYPE_MASK
#define KERNFS_TYPE_MASK 0x000f
#endif

#ifndef KERNFS_DIR
#define KERNFS_DIR 0x0001
#endif

struct caller_ctx {
  // --- Caller process PID. (TGID in the kernel) ---
  __u32 pid;

  // --- Caller cgroup ID ---
  __u64 cgid;
};

/* Helper Functions */
static __always_inline int is_protected_cgroup(__u64 cgid) {
  return TARGET_CGROUP != 0 && cgid == TARGET_CGROUP;
}

static __always_inline bool is_daemon_process(__u32 pid) {
  return DAEMON_PID != 0 && pid == DAEMON_PID;
}

static __always_inline void get_caller_ctx(struct caller_ctx* ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  ctx->pid  = (__u32) (pid_tgid >> 32);
  ctx->cgid = bpf_get_current_cgroup_id();
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
  struct caller_ctx caller = {};
  __u64             target_cgid;
  __u32             target_pid;

  if (ret) return ret;

  if (!child) return 0;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid)) return 0;

  target_cgid = task_cgroup_id(child);
  if (!is_protected_cgroup(target_cgid)) return 0;

  target_pid = BPF_CORE_READ(child, tgid);

  if (caller.pid == target_pid) return 0;

  bpf_printk("ptrace access denied: [caller pid=%u cgid=%llu]"
             " [target pid=%u cgid=%llu mode=%u] [protected cgid=%llu]\n",
             caller.pid, caller.cgid, target_pid, target_cgid, mode, TARGET_CGROUP);

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
  struct caller_ctx caller = {};
  __u64             parent_cgid;
  __u32             parent_pid;

  if (ret) return ret;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || !is_protected_cgroup(caller.cgid)) return 0;

  parent_cgid = parent ? task_cgroup_id(parent) : 0;
  parent_pid  = parent ? BPF_CORE_READ(parent, tgid) : 0;

  bpf_printk("ptrace_traceme denied: [caller pid=%u cgid=%llu]"
             " [parent pid=%u cgid=%llu] [protected cgid=%llu]\n",
             caller.pid, caller.cgid, parent_pid, parent_cgid, TARGET_CGROUP);
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
  struct caller_ctx caller = {};

  if (ret) return ret;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || !is_protected_cgroup(caller.cgid)) return 0;

  if (has_wx(reqprot) || has_wx(prot)) {
    bpf_printk("mmap_file denied: [caller pid=%u cgid=%llu]"
               " [reason=wx reqprot=%lu prot=%lu flags=%lu] [protected cgid=%llu]\n",
               caller.pid, caller.cgid, reqprot, prot, flags, TARGET_CGROUP);
    return -EPERM;
  }

  if (!file && (has_exec(reqprot) || has_exec(prot))) {
    bpf_printk("mmap_file denied: [caller pid=%u cgid=%llu]"
               " [reason=anonymous_exec reqprot=%lu prot=%lu flags=%lu] [protected cgid=%llu]\n",
               caller.pid, caller.cgid, reqprot, prot, flags, TARGET_CGROUP);
    return -EPERM;
  }
  // remove below?      useful, but requires files allowlisting or it is too harsh and blocks assault cube for example.
  //  (can block for dlopen("/tmp/cheat.so", RTLD_NOW);) but also many legitimate file-backed
  //  executable mappings.
  //
  //  APPROACH to collect baseline of legitimate executable mappings, client decides when to freeze,
  //  based on baseline we decide if this should be allowed/blocked... But also takes time to create
  //  such system..
  //

  // if (file && (has_exec(reqprot) || has_exec(prot))) {
  //   char path[256] = {};

  //   int path_len = bpf_path_d_path(&file->f_path, path, sizeof(path));

  //   if (path_len > 0) {
  //     bpf_printk("mmap_file denied: [caller pid=%u cgid=%llu]"
  //                " [reason=file_exec_map path=%s reqprot=%lu prot=%lu flags=%lu]"
  //                " [protected cgid=%llu]\n",
  //                caller.pid, caller.cgid,
  //                path, reqprot, prot, flags, TARGET_CGROUP);
  //   } else {
  //     bpf_printk("mmap_file denied: [caller pid=%u cgid=%llu]"
  //                " [reason=file_exec_map path=<unresolved> path_err=%d reqprot=%lu prot=%lu
  //                flags=%lu]" " [protected cgid=%llu]\n", caller.pid, caller.cgid, path_len,
  //                reqprot, prot, flags, TARGET_CGROUP);
  //   }

  //   return 0;
  // }

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
  struct caller_ctx caller = {};
  struct file*      backing_file;
  unsigned long     vm_flags;

  if (ret) return ret;

  if (!vma) return 0;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || !is_protected_cgroup(caller.cgid)) return 0;

  if (has_wx(reqprot) || has_wx(prot)) {
    bpf_printk("file_mprotect denied: [caller pid=%u cgid=%llu]"
               " [reason=wx reqprot=%lu prot=%lu] [protected cgid=%llu]\n",
               caller.pid, caller.cgid, reqprot, prot, TARGET_CGROUP);
    return -EPERM;
  }

  backing_file = BPF_CORE_READ(vma, vm_file);
  vm_flags     = BPF_CORE_READ(vma, vm_flags);

  if ((vm_flags & VM_WRITE) && (has_exec(reqprot) || has_exec(prot))) {
    bpf_printk("file_mprotect denied: [caller pid=%u cgid=%llu]"
               " [reason=writable_to_exec vm_flags=%lu reqprot=%lu prot=%lu]"
               " [protected cgid=%llu]\n",
               caller.pid, caller.cgid, vm_flags, reqprot, prot, TARGET_CGROUP);
    return -EPERM;
  }

  if (!backing_file && (has_exec(reqprot) || has_exec(prot))) {
    bpf_printk("file_mprotect denied: [caller pid=%u cgid=%llu]"
               " [reason=anonymous_exec reqprot=%lu prot=%lu] [protected cgid=%llu]\n",
               caller.pid, caller.cgid, reqprot, prot, TARGET_CGROUP);
    return -EPERM;
  }

  return 0;
}

/* inode_permission
 *
 */

SEC("lsm/inode_permission")
int BPF_PROG(restrict_inode_permission, struct inode* inode, int mask, int ret) {
  struct caller_ctx caller = {};
  unsigned long     sb_magic;

  if (ret) return ret;

  if (!inode) return 0;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || is_protected_cgroup(caller.cgid)) return 0;

  sb_magic = BPF_CORE_READ(inode, i_sb, s_magic);

  // --- CGROUPFS ---
  if (sb_magic == CGROUP2_SUPER_MAGIC) {
    struct kernfs_node* kn;
    struct kernfs_node* cg_kn;
    const char*         name_ptr;
    unsigned short      flags;
    __u64               target_cgid = 0;
    char                cg_name[32] = {};

    kn = (struct kernfs_node*) BPF_CORE_READ(inode, i_private);
    if (!kn) return 0;

    name_ptr = BPF_CORE_READ(kn, name);
    if (name_ptr) bpf_probe_read_kernel_str(cg_name, sizeof(cg_name), name_ptr);

    flags = BPF_CORE_READ(kn, flags);

    if ((flags & KERNFS_TYPE_MASK) == KERNFS_DIR) {
      cg_kn = kn;
    } else {
      cg_kn = BPF_CORE_READ(kn, __parent);
    }

    if (!cg_kn) return 0;

    target_cgid = BPF_CORE_READ(cg_kn, id);
    if (!target_cgid) return 0;

    if (is_protected_cgroup(target_cgid) && (mask & (MAY_WRITE | MAY_APPEND))) {
      bpf_printk("cgroupfs access denied: [caller pid=%u cgid=%llu]"
                 " [target cgid=%llu file=%s mask=%d] [protected cgid=%llu]\n",
                 caller.pid, caller.cgid, target_cgid, cg_name, mask, TARGET_CGROUP);

      return -EPERM;
    }
  }

  // --- PROCFS ---
  if (sb_magic == PROC_SUPER_MAGIC) {
    struct proc_inode*     pi;
    struct pid*            pid_ptr;
    struct proc_dir_entry* pde;
    const char*            name_ptr;
    char                   filename[32] = {};
    int                    target_pid   = 0;

    pi = container_of(inode, struct proc_inode, vfs_inode);

    pid_ptr = BPF_CORE_READ(pi, pid);

    if (pid_ptr) { target_pid = BPF_CORE_READ(pid_ptr, numbers[0].nr); }

    pde = BPF_CORE_READ(pi, pde);
    if (pde) {
      name_ptr = BPF_CORE_READ(pde, name);
      if (name_ptr) bpf_probe_read_kernel_str(filename, sizeof(filename), name_ptr);
    }

    if (target_pid == 0) { return 0; }
    struct task_struct* target_task = bpf_task_from_pid(target_pid);

    if (target_task) {
      __u64 target_cgid = task_cgroup_id(target_task);
      bpf_task_release(target_task);

      if (is_protected_cgroup(target_cgid)) {
        bpf_printk("procfs access denied: [caller pid=%u cgid=%llu]"
                   " [target pid=%d cgid=%llu file=/proc/%d/%s mask=%d] [protected cgid=%llu]\n",
                   caller.pid, caller.cgid, target_pid, target_cgid, target_pid, filename, mask,
                   TARGET_CGROUP);
        return -EPERM;
      }
    }
  }
  return 0;
}

/*
 * These hooks are cgroup-scoped mount protections.
 *
 * They deny mount/umount/pivot_root only when the CALLER is inside TARGET_CGROUP.
 *
 * They DO protect against:
 *   - game process mounting new filesystems
 *   - injected/helper process inside TARGET_CGROUP doing mount tricks
 *   - game process unmounting or pivot_root'ing its own namespace
 *
 * They DO NOT fully protect against:
 *   - an outside process already sharing the same mount namespace as the game
 *   - an outside process that entered the game mount namespace before this policy was active
 *   - an outside privileged process modifying shared mounts that propagate into the game namespace
 *
 * The procfs rule blocks outsiders from opening /proc/<game_pid>/ns/mnt,
 * which reduces the common setns() path into the game mount namespace.
 *
 * However, TARGET_MNT_NS would still be stronger because it lets us deny
 * mount operations based on the caller's current mount namespace, not only
 * based on caller.cgid.
 *
 * If we need that stronger protection:
 *   const volatile __u32 TARGET_MNT_NS = 0;
 *
 * Daemon can set it from:
 *   readlink /proc/<game_pid>/ns/mnt
 *
 * Also make the game mount namespace private/slave before launch to prevent
 * outside shared-mount propagation from affecting the game.
 */

SEC("lsm/sb_mount")
int BPF_PROG(restrict_sb_mount, const char* dev_name, const struct path* path, const char* type,
             unsigned long flags, void* data, int ret) {
  struct caller_ctx caller = {};

  if (ret) return ret;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || !is_protected_cgroup(caller.cgid)) return 0;

  bpf_printk("sb_mount denied: [caller pid=%u cgid=%llu]"
             " [flags=%lu] [protected cgid=%llu]\n",
             caller.pid, caller.cgid, flags, TARGET_CGROUP);

  return -EPERM;
}

SEC("lsm/sb_umount")
int BPF_PROG(restrict_sb_umount, struct vfsmount* mnt, int flags, int ret) {
  struct caller_ctx caller = {};

  if (ret) return ret;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || !is_protected_cgroup(caller.cgid)) return 0;

  bpf_printk("sb_umount denied: [caller pid=%u cgid=%llu]"
             " [flags=%d] [protected cgid=%llu]\n",
             caller.pid, caller.cgid, flags, TARGET_CGROUP);

  return -EPERM;
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(restrict_sb_pivotroot, const struct path* old_path, const struct path* new_path,
             int ret) {
  struct caller_ctx caller = {};

  if (ret) return ret;

  get_caller_ctx(&caller);

  if (is_daemon_process(caller.pid) || !is_protected_cgroup(caller.cgid)) return 0;

  bpf_printk("sb_pivotroot denied: [caller pid=%u cgid=%llu]"
             " [protected cgid=%llu]\n",
             caller.pid, caller.cgid, TARGET_CGROUP);

  return -EPERM;
}

/* bprm_check_security - Prevent LD_PRELOAD
 * 
 */

#ifndef MAX_ENV_SCAN
#define MAX_ENV_SCAN 256
#endif

#ifndef MAX_ENV_LEN
#define MAX_ENV_LEN 192
#endif

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32); // process PID / TGID
  __type(value, __u8);
} blocked_exec_pids SEC(".maps");

static __always_inline bool envp_has_ld_preload(const char* const* envp) {
  int i;

#pragma unroll
  for (i = 0; i < MAX_ENV_SCAN; i++) {
    const char* entry            = NULL;
    char        buf[MAX_ENV_LEN] = {};
    int         len;

    if (bpf_probe_read_user(&entry, sizeof(entry), &envp[i])) return false;

    if (!entry) return false;

    len = bpf_probe_read_user_str(buf, sizeof(buf), entry);
    if (len <= 0) continue;

    if (len >= 12 && buf[0] == 'L' && buf[1] == 'D' && buf[2] == '_' && buf[3] == 'P' &&
        buf[4] == 'R' && buf[5] == 'E' && buf[6] == 'L' && buf[7] == 'O' && buf[8] == 'A' &&
        buf[9] == 'D' && buf[10] == '=') {
      return true;
    }
  }

  return false;
}

static __always_inline void detect_ld_preload_from_envp(const char* const* envp) {
  struct caller_ctx caller = {};
  __u8              mark   = 1;

  get_caller_ctx(&caller);

  bpf_map_delete_elem(&blocked_exec_pids, &caller.pid);

  if (!envp) return;

  if (!is_protected_cgroup(caller.cgid)) return;

  if (envp_has_ld_preload(envp)) {
    bpf_map_update_elem(&blocked_exec_pids, &caller.pid, &mark, BPF_ANY);

    bpf_printk("LD_PRELOAD detected before exec: [caller pid=%u cgid=%llu] [protected cgid=%llu]\n",
               caller.pid, caller.cgid, TARGET_CGROUP);
  }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_ld_preload_execve(struct trace_event_raw_sys_enter* ctx) {
  detect_ld_preload_from_envp((const char* const*) ctx->args[2]);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int detect_ld_preload_execveat(struct trace_event_raw_sys_enter* ctx) {
  detect_ld_preload_from_envp((const char* const*) ctx->args[3]);
  return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_ld_preload_exec, struct linux_binprm* bprm, int ret) {
  struct caller_ctx caller = {};
  __u8*             mark;

  if (ret) return ret;

  get_caller_ctx(&caller);

  if (!is_protected_cgroup(caller.cgid)) {
    bpf_map_delete_elem(&blocked_exec_pids, &caller.pid);
    return 0;
  }

  mark = bpf_map_lookup_elem(&blocked_exec_pids, &caller.pid);
  if (!mark) return 0;

  bpf_map_delete_elem(&blocked_exec_pids, &caller.pid);

  bpf_printk("exec denied: [reason=LD_PRELOAD] [caller pid=%u cgid=%llu] [protected cgid=%llu]\n",
             caller.pid, caller.cgid, TARGET_CGROUP);

  return -EPERM;
}

char _license[] SEC("license") = "GPL";
