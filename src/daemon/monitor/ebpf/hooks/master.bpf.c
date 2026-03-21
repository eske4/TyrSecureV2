#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "Ebpf.h"


// This is the actual memory allocation (16MB in this case)
// A dummy program that exists just to make the ELF valid.
// You will LOAD this, but you will NEVER attach it.
char _license[] SEC("license") = "GPL";
