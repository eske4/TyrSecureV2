#include "EPollManager.hpp"
#include "EPollBinding.hpp"

namespace ACName::System {

EPollManager::~EPollManager() {
  for (auto &[file_descriptor, binding] : m_subscriptions) {
    if (binding != nullptr) {
      epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_DEL, file_descriptor, nullptr);
      binding->m_manager = nullptr;
      binding->m_active  = false;
    }
  }
}

std::expected<EPollManager, EPollError> EPollManager::create() {
  // EPOLL_CLOEXEC: Prevents the FD from leaking to child processes.
  int file_descriptor = epoll_create1(EPOLL_CLOEXEC);

  if (file_descriptor == -1) {
    return std::unexpected(EPollError::SysCallFailed);
  }

  // Return the object wrapped in 'expected'
  return EPollManager(FD(file_descriptor));
}

bool EPollManager::subscribe(int file_descriptor, EPollBinding *binding, uint32_t events) {
  if (binding == nullptr || file_descriptor < 0) {
    return false;
  }

  // Force Non-Blocking for Edge-Triggered mode
  // Check if flags contain EPOLLET and no a unsigned int with value 0
  if ((events & EPOLLET) != 0U) {
    const int current_flags = fcntl(file_descriptor, F_GETFL, 0);
    if (current_flags == -1) {
      return false;
    }

    // Check if O_NONBLOCK is missing using explicit bitwise comparison
    if ((static_cast<uint32_t>(current_flags) & O_NONBLOCK) == 0U) {
      if (fcntl(file_descriptor, F_SETFL, current_flags | O_NONBLOCK) == -1) {
        return false;
      }
    }
  }

  struct epoll_event event{};
  event.events   = events;
  event.data.ptr = binding; // The kernel now holds this raw address

  int ret = epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_ADD, file_descriptor, &event);
  if (ret == -1 && errno == EEXIST) {
    ret = epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_MOD, file_descriptor, &event);
  }

  if (ret == -1) {
    return false;
  }

  binding->m_active                = true;
  m_subscriptions[file_descriptor] = binding;
  return true;
}

bool EPollManager::unsubscribe(int file_descriptor, EPollBinding *binding) {
  // We pass nullptr because the kernel ignores the event arg for DEL
  if (binding == nullptr) {
    return false;
  }

  binding->m_active = false; // This "mutes" the binding for the current loop
                             //
  if (epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_DEL, file_descriptor, nullptr) == -1) {
    return false;
  }

  m_subscriptions.erase(file_descriptor);
  return true;
}

std::expected<size_t, EPollError> EPollManager::poll(int timeout_ms) {
  struct epoll_event local_events[MAX_EVENTS]; // 64
  size_t             total_processed = 0;

  for (int i = 0; i < MAX_RETRIES; ++i) {
    int nfds = epoll_wait(m_epoll_fd.get(), local_events, MAX_EVENTS, timeout_ms);

    if (nfds < 0) {
      if (errno == EINTR) {
        continue; // Just retry the wait
      }

      return std::unexpected(EPollError::SysCallFailed);
    }

    if (nfds == 0) {
      break; // Kernel is empty
    }

    // Dispatch the 64 events
    for (int j = 0; j < nfds; ++j) {
      auto *binding = static_cast<EPollBinding *>(local_events[j].data.ptr);
      if (binding != nullptr) {
        binding->dispatch(local_events[j].events);
        total_processed++;
      }
    }

    // If we got less than 64, we've cleared the "backlog"
    if (nfds < MAX_EVENTS) {
      break;
    }

    // If we're looping again to drain more, don't "halt" the game anymore
    timeout_ms = 0;
  }

  return total_processed;
}

} // namespace ACName::System
