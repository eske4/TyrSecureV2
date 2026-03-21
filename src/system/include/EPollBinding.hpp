#pragma once

#include <stdint.h>

// Forward declare to avoid header loops
namespace sys { 

class EPollManager;

class EPollBinding {
    friend class EPollManager;

private:
    static constexpr uint64_t MAGIC_CONSTANT = 0x5459524553454355;
    using Handler = void(*)(void* context, uint32_t events);

    uint64_t            m_instance_magic = MAGIC_CONSTANT;
    sys::EPollManager*  m_manager        = nullptr; // Initialize!
    int                 m_fd             = -1;      // Initialize!
    void*               m_ctx            = nullptr;
    Handler             m_on_event       = nullptr;
    bool                m_active         = false;

    void invalidate();

public:
    // Updated Constructor to actually receive the state
    EPollBinding(sys::EPollManager* manager, int file_descriptor, void* ctx, Handler handler); 
    ~EPollBinding();

    // Move Constructor: MUST transfer the manager and FD
    EPollBinding(EPollBinding&& other) noexcept; 

    // Disable copy
    EPollBinding(const EPollBinding&) = delete;
    EPollBinding& operator=(const EPollBinding&) = delete;

    // Standard Move Assignment (Optional but recommended)
    EPollBinding& operator=(EPollBinding&& other) noexcept;

    bool isValid() const noexcept {
        return (m_instance_magic == MAGIC_CONSTANT) && (m_on_event != nullptr) && m_active;
    }

    void dispatch(uint32_t events) const {
        if (isValid()) {
            m_on_event(m_ctx, events);
        }
    }
};
}
