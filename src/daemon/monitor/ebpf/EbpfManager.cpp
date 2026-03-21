#include "EbpfManager.hpp"
#include "EPollManager.hpp"
#include "Ebpf.h"
#include "master.skel.h"
#include <bpf/libbpf.h>
#include <cstdint>
#include <memory>
#include <stdint.h>
#include <sys/epoll.h>

EbpfManager::EbpfManager()
    : m_ringbuf_reader(nullptr, ring_buffer__free),
      m_master_skel(nullptr, master__destroy) // or skel if using skeleton
{}

int EbpfManager::handleEvent(void* ctx, void* data, size_t data_sz) {
    auto* self = static_cast<EbpfManager*>(ctx);
    if (self == nullptr || data == nullptr || data_sz != sizeof(common::ebpf_event)) {
        return 0;
    }

    const auto* event = static_cast<const common::ebpf_event*>(data);
    size_t index = static_cast<size_t>(event->module_id);

    if (index >= self->m_modules.size()) {
        return 0;
    }

    auto& mod = self->m_modules[index];
    if (mod) {

        mod->processEvent(event, data_sz);
    }
    return 0;
}

bool EbpfManager::start() {
    master *skel = master__open();
    if (skel == nullptr) {
        return false;
    }

    m_master_skel.reset(skel);

    if (master__load(m_master_skel.get()) < 0) {
        return false;
    }

    m_shared_rb_map = m_master_skel->maps.rb;
    if (m_shared_rb_map == nullptr) {
        return false;
    }

    m_shared_rb_fd = sys::FD(bpf_map__fd(m_shared_rb_map));

    auto* ring_buffer = ring_buffer__new(m_shared_rb_fd.get(), handleEvent, this, nullptr);
    if (ring_buffer == nullptr) {
        return false; // m_isActive remains false (default from constructor)
    }

    m_ringbuf_reader.reset(ring_buffer);
    
    // Set this ONLY when everything is guaranteed to work
    m_isActive = true; 
    return true;
}

bool EbpfManager::addModule(std::unique_ptr<IEbpfModule> mod){
    if(mod == nullptr || !m_isActive){
        return false;
    }

    size_t index = static_cast<size_t>(mod->getId());

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

bool EbpfManager::removeModule(common::bpf_module_id_t mod_id) {
    size_t index = static_cast<size_t>(mod_id);
    if (!m_isActive || index >= m_modules.size() || !m_modules[index]) {
        return false;
    }
    
    m_modules[index].reset();
    return true;
}

bool EbpfManager::createEPollBinding(sys::EPollManager* manager) {
    // Safety check: don't create if no ring buffer, no initilization and already have a binding
    if (manager == nullptr || m_ringbuf_reader == nullptr || m_binding != nullptr || !m_isActive) {
        return false;
    }

    int poll_fd = ring_buffer__epoll_fd(m_ringbuf_reader.get());
    if(poll_fd < 0) {
        return false; // Libbpf couldn't provide a pollable file descriptor
    }


    auto on_event = [](void* ctx, uint32_t events) {
        auto* self = static_cast<EbpfManager*>(ctx);
        // We only care about data being ready (EPOLLIN) 
        // or the buffer being closed (ERR/HUP)
        if (self && self->m_ringbuf_reader && (events & (EPOLLIN | EPOLLERR | EPOLLHUP))) {
            // consume() is more efficient than poll() when we already 
            // know data is there. It drains the buffer and calls handleEvent.
            ring_buffer__consume(self->m_ringbuf_reader.get());
        }
    };


    m_binding = std::make_unique<sys::EPollBinding>(
        manager, 
        poll_fd, 
        this, 
        on_event
    );

    if (!manager->subscribe(poll_fd, m_binding.get(), EPOLLIN | EPOLLET)) {
        m_binding.reset(); // Don't leave a dead binding object around
        return false;
    }

    return true;
}
