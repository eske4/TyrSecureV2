#pragma once

#include "daemon/bpf.h"
#include <bpf/libbpf.h>

class IEbpfModule {
public:
    virtual ~IEbpfModule() = default;

    // 1. Prepare the skeleton and maps
    virtual bool open() = 0;

    // 2. Load into kernel. If shared_fd is >= 0, reuse it for the "rb" map.
    virtual bool load(int shared_rb_fd) = 0;

    // 3. Attach to the kernel hooks (LSM, kprobe, tracepoint, etc.)
    virtual bool attach() = 0;
    virtual void processEvent(const common::ebpf_event* event, size_t size) = 0;
    virtual common::bpf_module_id_t getId() const = 0;

    // Optional: Get the name for logging/debugging
    virtual const char* getName() const = 0;
};
