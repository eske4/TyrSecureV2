#pragma once

#include "IEbpfModule.hpp"
#include "daemon/bpf.h"
#include "master.skel.h"
#include "system/EPoll.hpp"
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
    // The shared map (Ring Buffer)
    std::unique_ptr<EPollBinding> m_binding;
    static int handle_event(void *ctx, void *data, size_t data_sz);

public:
    EbpfManager();
    ~EbpfManager() = default;
    // Disable copying, allow moving
    EbpfManager(const EbpfManager&) = delete;
    EbpfManager& operator=(const EbpfManager&) = delete;

    EbpfManager(EbpfManager&&) = default;
    EbpfManager& operator=(EbpfManager&&) = default;

    bool start();
    bool add_module(std::unique_ptr<IEbpfModule> mod);
    bool remove_module(common::bpf_module_id_t mod_id);
    bool create_epoll_binding();
    int get_fd() const;
    EPollBinding* get_binding() const;
    
};

