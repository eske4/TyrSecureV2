#pragma once

#include "IEPollListener.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include <expected>
#include <memory>
#include <sys/epoll.h>
#include <sys/types.h>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace OdinSight::System {

class EPollManager {
private:
  /** --- Private Type Aliases & Constants --- **/
  using SubscriptionMap = std::unordered_map<int, std::unique_ptr<IEPollListener>>;

  static constexpr int MAX_EVENTS  = 64;
  static constexpr int MAX_RETRIES = 15;

  static constexpr std::string_view ctx = "EPollManager";

  /** --- Members (State) --- **/
  FD              m_epoll_fd;
  FD              m_sig_fd;
  SubscriptionMap m_subscriptions;
  bool            m_running{true};

  std::vector<int> m_pending_removal;

  /** --- Internal Interface (Called by EPollBinding) --- **/
  explicit EPollManager(FD&& epoll_fd, FD&& sig_fd)
      : m_epoll_fd(std::move(epoll_fd)), m_sig_fd(std::move(sig_fd)) {}

  void process_event(const struct epoll_event& event, size_t& total_processed);
  void process_unsubscriptions();

public:
  /** --- Lifecycle --- **/
  EPollManager() = delete;
  ~EPollManager();

  // Rule of Five: No copying, Move allowed
  EPollManager(const EPollManager&)            = delete;
  EPollManager& operator=(const EPollManager&) = delete;

  EPollManager(EPollManager&&) noexcept            = default;
  EPollManager& operator=(EPollManager&&) noexcept = default;

  [[nodiscard]] Odin::Result<void> subscribe(std::unique_ptr<IEPollListener> listener);
  [[nodiscard]] Odin::Result<void> unsubscribe(int file_descriptor);
  bool                             isRunning() const { return m_running; }

  /** --- Factory & Core Logic --- **/
  static Odin::Result<std::unique_ptr<EPollManager>> create();

  /**
   * @brief Wait for events on registered file descriptors.
   * @return Number of events processed, or an EPollError.
   */
  Odin::Result<size_t> poll(int timeout_ms = -1);
};

} // namespace OdinSight::System
