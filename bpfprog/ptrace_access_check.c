#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>


const volatile int protected_pid = 80511;


SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_proc, struct task_struct *child, unsigned int mode) {
    int target_pid = child->tgid;

    if(target_pid == protected_pid) {
        return -EPERM;
    }

    return 0;
}
