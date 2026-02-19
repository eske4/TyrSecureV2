#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENV_SCAN 256
#define MAX_ENV_LEN 192

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u8);
} block_exec_tgid SEC(".maps");

static __always_inline bool has_ld_preload_prefix(const char *s, int len)
{
    /*
     * bpf_probe_read_user_str() length includes trailing NUL.
     * "LD_PRELOAD=" is 11 bytes without NUL.
     */
    if (len < 12)
        return false;

    return s[0] == 'L' && s[1] == 'D' && s[2] == '_' && s[3] == 'P' &&
           s[4] == 'R' && s[5] == 'E' && s[6] == 'L' && s[7] == 'O' &&
           s[8] == 'A' && s[9] == 'D' && s[10] == '=';
}

static __always_inline bool envp_has_ld_preload(const char *const *envp)
{
    int i;

#pragma unroll
    for (i = 0; i < MAX_ENV_SCAN; i++) {
        const char *entry;
        char buf[MAX_ENV_LEN];
        int len;

        if (bpf_probe_read_user(&entry, sizeof(entry), &envp[i]))
            return false;
        if (!entry)
            return false;

        len = bpf_probe_read_user_str(buf, sizeof(buf), entry);
        if (len <= 0)
            continue;

        if (has_ld_preload_prefix(buf, len))
            return true;
    }

    return false;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_ld_preload_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *const *envp = (const char *const *)ctx->args[2];
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u8 one = 1;

    if (!envp)
        return 0;

    if (envp_has_ld_preload(envp))
        bpf_map_update_elem(&block_exec_tgid, &tgid, &one, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int detect_ld_preload_execveat(struct trace_event_raw_sys_enter *ctx)
{
    const char *const *envp = (const char *const *)ctx->args[3];
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u8 one = 1;

    if (!envp)
        return 0;

    if (envp_has_ld_preload(envp))
        bpf_map_update_elem(&block_exec_tgid, &tgid, &one, BPF_ANY);

    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_ld_preload_exec, struct linux_binprm *bprm, int ret)
{
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u8 *marked;

    if (ret)
        return ret;

    marked = bpf_map_lookup_elem(&block_exec_tgid, &tgid);
    if (marked) {
        bpf_map_delete_elem(&block_exec_tgid, &tgid);
        bpf_printk("Blocked exec due to LD_PRELOAD");
        return -EPERM;
    }

    return 0;
}
