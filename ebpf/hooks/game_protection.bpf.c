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
    // 1. Is this procfs?
    if (BPF_CORE_READ(inode, i_sb, s_magic) != 0x9fa0) {
        return 0;
    }

    // 2. Is the CALLER the game? If so, allow.
    if (bpf_get_current_cgroup_id() == TARGET_CGROUP) {
        return 0;
    }

    // 3. The Modern Cast: Treat the inode as a proc_inode
    // This replaces the "weird macro" logic.
    struct proc_inode *ei = bpf_core_cast(inode, struct proc_inode);
    
    // 4. Follow the path to the task
    struct pid *pid_struct = BPF_CORE_READ(ei, pid);
    if (!pid_struct) return 0;

    struct task_struct *target_task = (struct task_struct *)BPF_CORE_READ(pid_struct, tasks[0].first);
    if (!target_task) return 0;

    // 5. Check the Target's Cgroup
    struct cgroup *cg = BPF_CORE_READ(target_task, cgroups, dfl_cgrp);
    __u64 target_cg_id = BPF_CORE_READ(cg, kn, id);

    // 6. Block if target is in the group and caller is not
    if (target_cg_id == TARGET_CGROUP) {
        return -13; // -EPERM
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
