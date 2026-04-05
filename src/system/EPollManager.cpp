#include "EPollManager.hpp"
#include "common/Result.hpp"
#include <algorithm>
#include <csignal>
#include <fcntl.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace OdinSight::System {

using Error = Odin::Error;
EPollManager::~EPollManager() {
  if (!m_epoll_fd) { return; }

  for (auto const& [file_descriptor, listener] : m_subscriptions) {
    ::epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_DEL, file_descriptor, nullptr);
  }

  m_subscriptions.clear();

  m_running = false;
}

Odin::Result<std::unique_ptr<EPollManager>> EPollManager::create() {
  int raw_ep_fd = ::epoll_create1(EPOLL_CLOEXEC);

  if (raw_ep_fd == -1) { return std::unexpected(Error::System(ctx, "epoll_create", errno)); }

  auto ep_fd = FD::adopt(raw_ep_fd);

  if (!ep_fd) {
    return std::unexpected(Error::Logic(ctx, "adopt_epoll", "Failed to adopt epoll FD"));
  }

  // --- INTERNAL SIGNAL SETUP ---
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);

  // Block signals so they don't terminate the process immediately
  if (::sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    return std::unexpected(Error::System(ctx, "sigprocmask", errno));
  }

  // Create the signalfd
  int raw_sig = ::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (raw_sig == -1) {
    // If we return here, ep_fd's destructor runs and closes the epoll FD.
    return std::unexpected(Error::System(ctx, "signalfd_create", errno));
  }
  auto sig_fd = FD::adopt(raw_sig);
  if (!sig_fd) {
    return std::unexpected(Error::Logic(ctx, "adopt_signal", "Failed to adopt signal FD"));
  }

  // 4. Register signalfd with epoll
  struct epoll_event event{};
  event.events  = EPOLLIN;
  // We explicitly set ptr to nullptr so the 'else' block in poll() is triggered
  event.data.fd = sig_fd->get();
  if (::epoll_ctl(ep_fd->get(), EPOLL_CTL_ADD, sig_fd->get(), &event) == -1) {
    return std::unexpected(Error::System(ctx, "epoll_add_signal", errno));
  }

  return std::unique_ptr<EPollManager>(
      new EPollManager(std::move(ep_fd.value()), std::move(sig_fd.value())));
}

Odin::Result<void> EPollManager::subscribe(std::unique_ptr<IEPollListener> listener) {
  // 1. Basic Validation
  if (listener == nullptr) {
    return std::unexpected(Error::Logic(ctx, "subscribe", "Null listener provided"));
  }

  const FD& file_descriptor = listener->getFd();
  uint32_t  events          = listener->getEvents();
  if (file_descriptor.get() < 0) {
    return std::unexpected(Error::Logic(ctx, "subscribe", "Invalid listener FD"));
  }

  // 2. Force Non-Blocking for Edge-Triggered mode (EPOLLET)
  if ((events & EPOLLET) != 0U) {
    const int current_flags = ::fcntl(file_descriptor.get(), F_GETFL, 0);
    if (current_flags == -1) { return std::unexpected(Error::System(ctx, "fcntl_get", errno)); }

    if ((static_cast<uint32_t>(current_flags) & O_NONBLOCK) == 0U) {
      if (::fcntl(file_descriptor.get(), F_SETFL, current_flags | O_NONBLOCK) == -1) {
        return std::unexpected(Error::System(ctx, "fcntl_set_nonblock", errno));
      }
    }
  }

  // 3. Prepare epoll_event
  struct epoll_event event{};
  event.events   = events;
  // CRITICAL: We store the interface pointer so poll() can call it directly
  event.data.ptr = listener.get();

  if (!m_epoll_fd) {
    return std::unexpected(Error::Logic(ctx, "subscribe", "Manager epoll FD is invalid"));
  }

  // 4. Register with Kernel
  int ret = ::epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_ADD, file_descriptor.get(), &event);

  // If it already exists, modify it instead (standard robustness)
  if (ret == -1 && errno == EEXIST) {
    ret = ::epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_MOD, file_descriptor.get(), &event);
  }

  if (ret == -1) { return std::unexpected(Error::System(ctx, "epoll_ctl_add", errno)); }

  // 5. Track the subscription internally
  m_subscriptions[file_descriptor.get()] = std::move(listener);

  return {};
}

Odin::Result<void> EPollManager::unsubscribe(int file_descriptor) {
  // 1. Basic Validation
  if (file_descriptor < 0 || !m_epoll_fd) {
    return std::unexpected(Error::Logic(ctx, "unsubscribe", "Invalid FD or Manager state"));
  }

  // 3. Remove from Kernel

  if (::epoll_ctl(m_epoll_fd.get(), EPOLL_CTL_DEL, file_descriptor, nullptr) == -1) {
    // If the FD was already closed or removed, we might get EBADF or ENOENT.
    // We only return an error if it's a "real" failure.
    if (errno != ENOENT && errno != EBADF) {
      return std::unexpected(Error::System(ctx, "epoll_ctl_del", errno));
    }
  }

  m_pending_removal.push_back(file_descriptor);

  // 4. Cleanup internal tracking
  // extract() removes the item from the map but keeps the object

  return {};
}

Odin::Result<size_t> EPollManager::poll(int timeout_ms) {
  struct epoll_event local_events[MAX_EVENTS];
  size_t             total_processed = 0;

  if (!m_epoll_fd) { return std::unexpected(Error::Logic(ctx, "poll", "Epoll FD is null")); }

  for (int i = 0; i < MAX_RETRIES; ++i) {
    int nfds = epoll_wait(m_epoll_fd.get(), local_events, MAX_EVENTS, timeout_ms);

    if (nfds < 0) {
      if (errno == EINTR) { continue; }
      return std::unexpected(Error::System(ctx, "epoll_wait", errno));
    }

    if (nfds == 0) { break; }

    // --- THE CLEAN DISPATCH LOOP ---
    for (int j = 0; j < nfds; ++j) { process_event(local_events[j], total_processed); }

    // Break if we've drained the kernel buffer
    if (static_cast<size_t>(nfds) < MAX_EVENTS) { break; }
    timeout_ms = 0;
  }

  process_unsubscriptions();

  return total_processed;
}

void EPollManager::process_event(const struct epoll_event& event, size_t& total_processed) {
  // 1. Signal Check: Use the .fd member of the union.
  // If this matches, we stop here.
  if (m_sig_fd && event.data.fd == m_sig_fd.get()) {
    struct signalfd_siginfo fdsi;
    while (::read(m_sig_fd.get(), &fdsi, sizeof(fdsi)) > 0) { m_running = false; }
    return;
  }

  // 2. Listener Dispatch: Now it's safe to treat the union as a .ptr.
  auto* listener = static_cast<IEPollListener*>(event.data.ptr);
  if (listener == nullptr) { return; }

  // 3. Pending Removal Check
  // Get FD from the object itself to verify against the removal list
  const int file_descriptor = listener->getFd().get();
  if (std::ranges::contains(m_pending_removal, file_descriptor)) { return; }

  // 4. Execute
  listener->onEpollEvent(event.events);
  total_processed++;
}

void EPollManager::process_unsubscriptions() {
  if (m_pending_removal.empty()) { return; }

  for (int file_descriptor : m_pending_removal) { m_subscriptions.erase(file_descriptor); }

  m_pending_removal.clear();
}
} // namespace OdinSight::System
