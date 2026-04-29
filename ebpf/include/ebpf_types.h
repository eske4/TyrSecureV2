#pragma once

#ifdef __cplusplus
#include <cstdint>
#include <linux/types.h>
#include <stddef.h>
namespace OdinSight::Daemon::Monitor::Kernel {
// We don't use extern "C" here because C++ enums/namespaces
// aren't compatible with C anyway. We just keep the layout identical.
enum class EbpfModuleId : uint32_t {
  MODULE_DAEMON = 0,
  MODULE_GAME,
  MODULE_COUNT,
};

static constexpr size_t EBPF_MODULES_COUNT = static_cast<size_t>(EbpfModuleId::MODULE_COUNT);

struct ebpf_event {
  __u64        timestamp;
  EbpfModuleId module_id;
  __u32        hook_id;
  __u32        event_type;
} __attribute__((packed));

} // namespace OdinSight::Daemon::Monitor::Kernel
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
  __u32        hook_id;
  __u32        event_type;
} __attribute__((packed));

#define MODULE_DAEMON 0
#define MODULE_GAME   1

#endif
