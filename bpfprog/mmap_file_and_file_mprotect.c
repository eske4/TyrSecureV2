#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * UAPI protection bits (asm-generic/mman-common.h).
 * vmlinux.h exposes kernel types/structs, not these user ABI macros.
 */
#define TARGET_TGID 29905
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

static __always_inline bool has_wx(unsigned long prot)
{
    return (prot & PROT_WRITE) && (prot & PROT_EXEC);
}

static __always_inline bool has_exec(unsigned long prot)
{
    return prot & PROT_EXEC;
}

static __always_inline char to_lower_ascii(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static __always_inline bool is_linux_so_name(const char *name, int len)
{
    int last, i;

    if (len < 4)
        return false;

    /* len includes trailing NUL */
    last = len - 2;

    if (name[last - 2] == '.' &&
        to_lower_ascii(name[last - 1]) == 's' &&
        to_lower_ascii(name[last]) == 'o')
        return true;

    for (i = last; i >= 3; i--) {
        if (name[i] != '.')
            continue;

        if (name[i - 3] == '.' &&
            to_lower_ascii(name[i - 2]) == 's' &&
            to_lower_ascii(name[i - 1]) == 'o')
            return true;
    }

    return false;
}

static __always_inline bool is_target_tgid(void)
{
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    return tgid == TARGET_TGID;
}

SEC("lsm/mmap_file")
int BPF_PROG(protect_so_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    struct dentry *dentry;
    const unsigned char *name_ptr;
    char name[128];
    int len;

    if (ret)
        return ret;

    if (!is_target_tgid())
        return 0;

    if (has_wx(reqprot) || has_wx(prot)) {
        bpf_printk("Blocked mmap_file W+X mapping");
        return -EPERM;
    }

    if (!file && (has_exec(reqprot) || has_exec(prot))) {
        bpf_printk("Blocked mmap_file anonymous exec");
        return -EPERM;
    }

    if (!file || !(has_exec(reqprot) || has_exec(prot)))
        return 0;

    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (!name_ptr)
        return 0;

    len = bpf_core_read_str(name, sizeof(name), name_ptr);
    if (len <= 0)
        return 0;

    if (is_linux_so_name(name, len)) {
        bpf_printk("Blocked mmap_file exec mapping of .so: %s", name);
        return -EPERM;
    }

    return 0;
}


SEC("lsm/file_mprotect")
int BPF_PROG(block_wx_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    struct file *backing_file;

    if (ret)
        return ret;

    if (!is_target_tgid())
        return 0;

    if (has_wx(reqprot) || has_wx(prot)) {
        bpf_printk("Blocked file_mprotect W+X transition");
        return -EPERM;
    }

    backing_file = BPF_CORE_READ(vma, vm_file);

    /*
     * Block RW->RX style transitions used by many in-memory injection flows.
     * If region is/was writable and caller asks for EXEC, deny.
     */
    if ((has_exec(reqprot) || has_exec(prot)) &&
        ((reqprot & PROT_WRITE) || (prot & PROT_WRITE))) {
        bpf_printk("Blocked file_mprotect writable-to-exec transition");
        return -EPERM;
    }

    /* Also deny anonymous memory being promoted to executable. */
    if (!backing_file && (has_exec(reqprot) || has_exec(prot))) {
        bpf_printk("Blocked file_mprotect anonymous exec transition");
        return -EPERM;
    }

    return 0;
}
