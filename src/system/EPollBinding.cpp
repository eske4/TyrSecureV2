#include "EPollBinding.hpp"
#include "EPollManager.hpp"

namespace sys {
void EPollBinding::invalidate() {
        m_instance_magic = 0;
        m_fd             = -1;
        m_manager        = nullptr;
        m_active         = false;
        m_on_event       = nullptr;
        m_ctx            = nullptr;
}

    // Updated Constructor to actually receive the state
EPollBinding::EPollBinding(EPollManager* manager, int file_descriptor, void* ctx, Handler handler) 
        : m_manager(manager), m_fd(file_descriptor), m_ctx(ctx), m_on_event(handler) {}

EPollBinding::~EPollBinding() {
        // ONLY unsubscribe if we actually have a manager and a valid FD
    if (m_manager != nullptr && m_fd >= 0) {
        m_manager->unsubscribe(m_fd, this);
    }
    invalidate();
}

    // Move Constructor: MUST transfer the manager and FD
EPollBinding::EPollBinding(EPollBinding&& other) noexcept {
    if (this != &other) { // Safety check
        m_instance_magic = other.m_instance_magic;
        m_manager        = other.m_manager;
        m_fd             = other.m_fd;
        m_ctx            = other.m_ctx;
        m_on_event       = other.m_on_event;
        m_active         = other.m_active;

        other.invalidate(); 
    }
}

EPollBinding& EPollBinding::operator=(EPollBinding&& other) noexcept {
        if (this != &other) {
            // If THIS object was already holding a subscription, 
            // the destructor logic should trigger or we manually clean up:
            if (m_manager != nullptr && m_fd >= 0)  {
                m_manager->unsubscribe(m_fd, this);
            }

            m_manager  = other.m_manager;
            m_fd       = other.m_fd;
            m_ctx      = other.m_ctx;
            m_on_event = other.m_on_event;
            m_active   = other.m_active;
            
            other.invalidate();
        }
        return *this;
    }
}
