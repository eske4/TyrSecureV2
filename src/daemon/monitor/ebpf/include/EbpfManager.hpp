#pragma once

#include "IEbpfModule.hpp"
#include "master.skel.h"
#include "EPollBinding.hpp"
#include "system/FD.hpp"
#include <array>
#include <bpf/libbpf.h>
#include <memory>

class EbpfManager {
private:
    using ModuleArray = std::array<
        std::unique_ptr<IEbpfModule>,
        static_cast<size_t>(common::bpf_module_id_t::MODULE_COUNT)
    >;

    ModuleArray m_modules;
    std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> m_ringbuf_reader;
    std::unique_ptr<struct master, decltype(&master__destroy)> m_master_skel;
    sys::FD m_shared_rb_fd; 
    struct bpf_map* m_shared_rb_map = nullptr;
    std::unique_ptr<sys::EPollBinding> m_binding;
    bool m_isActive = false;

    static int handleEvent(void *ctx, void* data, size_t data_sz);

public:
    EbpfManager();
    ~EbpfManager() = default;
    // Disable copying, allow moving
    EbpfManager(const EbpfManager&) = delete;
    EbpfManager& operator=(const EbpfManager&) = delete;

    EbpfManager(EbpfManager&&) = default;
    EbpfManager& operator=(EbpfManager&&) = default;

    [[nodiscard]] bool start();
    [[nodiscard]] bool addModule(std::unique_ptr<IEbpfModule> mod);
    [[nodiscard]] bool removeModule(common::bpf_module_id_t mod_id);
    [[nodiscard]] bool createEPollBinding(sys::EPollManager* manager);
};

