#include "EbpfManager.hpp"
#include "daemon/bpf.h"
#include "master.skel.h"
#include <bpf/libbpf.h>
#include <cstdint>
#include <memory>
#include <sys/epoll.h>

EbpfManager::EbpfManager()
    : m_ringbuf_reader(nullptr, ring_buffer__free),
      m_master_skel(nullptr, master__destroy) // or skel if using skeleton
{}

int EbpfManager::handle_event(void* ctx, void* data, size_t data_sz) {
    auto* self = static_cast<EbpfManager*>(ctx);
    if (self == nullptr || data == nullptr) {
        return 0;
    }

    if (data_sz != sizeof(common::ebpf_event)){
        return 0;
    } 

    const auto* event = static_cast<const common::ebpf_event*>(data);
    size_t index = static_cast<size_t>(event->module_id);

    if (index >= self->m_modules.size()) {
        return 0;
    }

    auto& mod = self->m_modules[index];
    if (mod) {

        mod->process_event(event, data_sz);
    }
    return 0;
}

bool EbpfManager::start() {
    master *skel = master__open();
    if (skel == nullptr) {
        return false;
    }

    if (master__load(skel) < 0) {
        master__destroy(skel);
        return false;
    }

    // Take ownership FIRST (RAII Safety)
    m_master_skel.reset(skel);

    // Get shared ring buffer map
    m_shared_rb_map = skel->maps.rb;
    if(this->m_shared_rb_map == nullptr){
        return false;
    }

    // Store FD once
    m_shared_rb_fd = sys::FD(bpf_map__fd(m_shared_rb_map));

    // Create reader
    m_ringbuf_reader.reset(ring_buffer__new(m_shared_rb_fd.get(), handle_event, this, nullptr));


    if(m_ringbuf_reader == nullptr) {
        return false;
    }

    return true;
}

bool EbpfManager::add_module(std::unique_ptr<IEbpfModule> mod){
    if(mod == nullptr){
        return false;
    }

    size_t index = static_cast<size_t>(mod->get_id());

    if (index >= m_modules.size()) {
        return false;
    }

    // Only attempt to load if the manager is ready
    if (m_ringbuf_reader && m_shared_rb_fd.isValid()) {
        int shared_fd = m_shared_rb_fd.get();

        if (!mod->open()) {
            return false;
        }

        if (!mod->load(shared_fd)) {
            return false; // Redirection
        }

        if (!mod->attach()) {
            return false;
        }
    }

    m_modules[index] = std::move(mod);
    return true;
}

bool EbpfManager::remove_module(common::bpf_module_id_t mod_id) {
    size_t index = static_cast<size_t>(mod_id);
    if (index >= m_modules.size() || !m_modules[index]) {
        return false;
    }
    
    m_modules[index].reset();
    return true;
}

bool EbpfManager::create_epoll_binding() {
    // Safety check: don't create if no ring buffer or already have a binding
    if (m_ringbuf_reader == nullptr || m_binding != nullptr) {
        return false;
    }


    m_binding = std::make_unique<EPollBinding>();
    m_binding->context = this;
    m_binding->active = true;

    m_binding->on_event = [](void* ctx, uint32_t events) {
        auto* self = static_cast<EbpfManager*>(ctx);
        if (!self || !self->m_ringbuf_reader) {
            return;
        }

        // EPOLLIN: New data is ready
        // EPOLLERR/HUP: The kernel side of the buffer closed or errored
        if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
            ring_buffer__poll(self->m_ringbuf_reader.get(), 0);
        }
    };

    return true;
}

int EbpfManager::get_fd() const {
    // We check if 'rb' exists because if start() hasn't been called, 
    // or if it failed, 'rb' will be nullptr.
    if (this->m_ringbuf_reader == nullptr) {
        return -1;
    }

    // ring_buffer__epoll_fd is a libbpf helper that returns the 
    // epoll-compatible FD for the buffer notification channel.
    return ring_buffer__epoll_fd(m_ringbuf_reader.get());
}

EPollBinding* EbpfManager::get_binding() const {
    return m_binding.get();
}


