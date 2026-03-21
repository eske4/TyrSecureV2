#pragma once

#include "system/FD.hpp"
#include <expected>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

namespace sys{

static constexpr int MAX_EVENTS = 64;
static constexpr int MAX_RETRIES = 15;

// Forward declaration!
class EPollBinding;

enum class EPollError : uint8_t {
    Interrupted = 0,
    SysCallFailed = 1,
    Timeout = 2,
    InvalidFD = 3
};

class EPollManager {
private:
  sys::FD m_epoll_fd;
  std::unordered_map<int, EPollBinding*> m_subscriptions;
  explicit EPollManager(sys::FD&& file_descriptor) : m_epoll_fd(std::move(file_descriptor)) {}

public:
  ~EPollManager();

  // Disable copying
  EPollManager(const EPollManager&) = delete;
  EPollManager& operator=(const EPollManager&) = delete;

  // Allow moving
  EPollManager(EPollManager&&) noexcept = default;


  static std::expected<EPollManager, EPollError> create();
  bool subscribe(int file_descriptor, EPollBinding *binding, uint32_t flags);
  bool unsubscribe(int file_descriptor, EPollBinding* binding);
  std::expected<size_t, EPollError> poll(int timeout_ms = -1);
};

}
