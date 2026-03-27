#pragma once

#include <expected>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include "system/FD.hpp"

namespace OdinSight::System {

/** --- Error Types --- **/
enum class EPollError : uint8_t { Interrupted = 0, SysCallFailed = 1, Timeout = 2, InvalidFD = 3 };

// Forward declaration
class EPollBinding;

class EPollManager {
  friend class EPollBinding;

private:
  /** --- Private Type Aliases & Constants --- **/
  using SubscriptionMap = std::unordered_map<int, EPollBinding *>;

  static constexpr int MAX_EVENTS  = 64;
  static constexpr int MAX_RETRIES = 15;

  /** --- Members (State) --- **/
  FD              m_epoll_fd;
  SubscriptionMap m_subscriptions;

  /** --- Internal Interface (Called by EPollBinding) --- **/
  explicit EPollManager(FD &&file_descriptor) : m_epoll_fd(std::move(file_descriptor)) {}

  [[nodiscard]] bool subscribe(int file_descriptor, EPollBinding *binding, uint32_t events);
  [[nodiscard]] bool unsubscribe(int file_descriptor, EPollBinding *binding);

public:
  /** --- Lifecycle --- **/
  ~EPollManager();

  // Rule of Five: No copying, Move allowed
  EPollManager(const EPollManager &)            = delete;
  EPollManager &operator=(const EPollManager &) = delete;

  EPollManager(EPollManager &&) noexcept            = default;
  EPollManager &operator=(EPollManager &&) noexcept = default;

  /** --- Factory & Core Logic --- **/
  static std::expected<EPollManager, EPollError> create();

  /**
   * @brief Wait for events on registered file descriptors.
   * @return Number of events processed, or an EPollError.
   */
  std::expected<size_t, EPollError> poll(int timeout_ms = -1);
};

} // namespace OdinSight::System
