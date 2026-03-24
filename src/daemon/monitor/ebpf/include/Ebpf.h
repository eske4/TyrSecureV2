#pragma once

#ifdef __cplusplus
#include <cstdint>
#include <linux/types.h>
namespace ACName::Daemon::Monitor::Kernel {
// We don't use extern "C" here because C++ enums/namespaces
// aren't compatible with C anyway. We just keep the layout identical.
enum class EbpfModuleId : uint32_t {
  MODULE_LSM_SHIELD   = 0,
  MODULE_MEM_WATCHER  = 1,
  MODULE_PROC_MONITOR = 2,
  MODULE_COUNT        = 3
};

struct ebpf_event {
  __u64        timestamp;
  EbpfModuleId module_id;
  __u32        event_type;
} __attribute__((packed));

} // namespace ACName::Daemon::Monitor::Kernel
#else

/* --- BPF C SIDE --- */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

typedef __u32 EbpfModuleId;

struct ebpf_event {
  __u64        timestamp;
  EbpfModuleId module_id;
  __u32        event_type;
} __attribute__((packed));

#define MODULE_LSM_SHIELD 0
#define MODULE_MEM_WATCHER 1
#define MODULE_PROC_MONITOR 2

#endif
