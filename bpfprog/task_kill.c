#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>


const volatile int protected_pid = 80511;


SEC("lsm/task_kill")
int BPF_PROG(prevent_closure_of_ts, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    int target_pid = p->tgid;
    if (target_pid == protected_pid) {
        // Return -EPERM (Operation not permitted) to block the signal
        return -EPERM;
    } 

    return 0;
}

