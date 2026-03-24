#include "EPollBinding.hpp"
#include "EPollManager.hpp"

namespace ACName::System {
void EPollBinding::invalidate() {
  m_instance_magic = 0;
  m_fd             = -1;
  m_manager        = nullptr;
  m_active         = false;
  m_on_event       = nullptr;
  m_ctx            = nullptr;
  m_event_mask     = 0;
}

// Updated Constructor to actually receive the state
EPollBinding::EPollBinding(EPollManager *manager, int file_descriptor, void *ctx, Handler handler)
    : m_manager(manager), m_fd(file_descriptor), m_ctx(ctx), m_on_event(handler) {}

EPollBinding::~EPollBinding() {
  // ONLY unsubscribe if we actually have a manager and a valid FD
  if (m_manager != nullptr && m_fd >= 0) {
    (void)m_manager->unsubscribe(m_fd, this);
  }
  invalidate();
}

// Move Constructor: MUST transfer the manager and FD
EPollBinding::EPollBinding(EPollBinding &&other) noexcept {
  if (this != &other) { // Safety check
    m_instance_magic = other.m_instance_magic;
    m_manager        = other.m_manager;
    m_fd             = other.m_fd;
    m_ctx            = other.m_ctx;
    m_on_event       = other.m_on_event;
    m_active         = other.m_active;
    m_event_mask     = other.m_event_mask;

    other.invalidate();
  }
}

EPollBinding &EPollBinding::operator=(EPollBinding &&other) noexcept {
  if (this != &other) {
    // If THIS object was already holding a subscription,
    // the destructor logic should trigger or we manually clean up:
    if (m_manager != nullptr && m_fd >= 0) {
      (void)m_manager->unsubscribe(m_fd, this);
    }

    m_instance_magic = other.m_instance_magic;
    m_manager        = other.m_manager;
    m_fd             = other.m_fd;
    m_ctx            = other.m_ctx;
    m_on_event       = other.m_on_event;
    m_active         = other.m_active;
    m_event_mask     = other.m_event_mask;

    other.invalidate();
  }
  return *this;
}

bool EPollBinding::unsubscribe() {
  if (!m_active) {
    return true; // Already paused, no work needed
  }

  if (m_manager != nullptr && m_manager->unsubscribe(m_fd, this)) {
    m_active     = false;
    m_event_mask = 0;
    return true;
  }
  return false; // Manager failed to talk to the kernel
}

bool EPollBinding::subscribe(uint32_t events) {
  if (m_active && m_event_mask == events) {
    return true; // Already active
  }

  // Assuming your manager's subscribe returns a bool
  if (m_manager != nullptr && m_manager->subscribe(m_fd, this, events)) {
    m_active     = true;
    m_event_mask = events;
    return true;
  }
  return false;
}

} // namespace ACName::System
