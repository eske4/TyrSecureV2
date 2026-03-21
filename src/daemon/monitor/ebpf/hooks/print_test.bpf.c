#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Ebpf.h"
#include <errno.h>

char LICENSE[] SEC("license") = "GPL";
const volatile int protected_pid = 2197677;


SEC("lsm/task_kill")
int BPF_PROG(prevent_closure_of_ts, struct task_struct *p,
             struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    int target_pid = p->tgid;

    // Create event
    struct ebpf_event e = {};
    e.timestamp = bpf_ktime_get_ns();
    e.module_id = MODULE_LSM_SHIELD;  // must match your SyscallModule::get_id()
    e.event_type = 1;                 // you can define multiple event types if you want

    // Push event to shared ring buffer
    bpf_ringbuf_output(&rb, &e, sizeof(e), 0);

    if (target_pid == protected_pid) {
        return -EPERM;
    }

    return 0;
}

