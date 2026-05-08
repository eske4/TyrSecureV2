#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "ebpf_types.h"

// This is the actual memory allocation (16MB in this case)
// A dummy program that exists just to make the ELF valid.
// You will LOAD this, but you will NEVER attach it.

const volatile __u64 TARGET_CGROUP = 0;

SEC("lsm/inode_permission")
int BPF_PROG(block_proc_selective, struct inode *inode, int mask)
{
    // 1. Only care about ProcFS
    if (BPF_CORE_READ(inode, i_sb, s_magic) != 0x9fa0) return 0;

    // 2. Fast Caller Check
    __u64 caller_cg_id = bpf_get_current_cgroup_id();
    if (caller_cg_id == TARGET_CGROUP) return 0;

    // 3. Resolve PID from Inode
    struct proc_inode *ei = bpf_core_cast(inode, struct proc_inode);
    struct pid *pid_ptr = BPF_CORE_READ(ei, pid);
    if (!pid_ptr) return 0;

    s32 pid_nr = BPF_CORE_READ(pid_ptr, numbers[0].nr);
    if (pid_nr <= 0) return 0;

    // 4. Resolve Task from PID (The "Universal" way)
    struct task_struct *target_task = bpf_task_from_pid(pid_nr);
    if (!target_task) return 0;

    // 5. Cgroup Check
    __u64 target_cg_id = BPF_CORE_READ(target_task, cgroups, dfl_cgrp, kn, id);
    bpf_task_release(target_task);

    if (target_cg_id == TARGET_CGROUP) {
        bpf_printk("BLOCK: PID %d is protected. Caller CG: %llu", pid_nr, caller_cg_id);
        return -EACCES;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
