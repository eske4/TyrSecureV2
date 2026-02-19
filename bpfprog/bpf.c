#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>


const volatile int protected_pid = 80511;
const volatile int loader_pid = 0; 
bool is_dev = true;



SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_to_self, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (is_dev) {
        is_dev = false;
        return 0; // Let bpftool do its thing
    }

    return -EPERM; 
}

