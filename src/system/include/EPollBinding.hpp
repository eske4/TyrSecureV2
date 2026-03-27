#pragma once

#include <cstdint>
#include <sys/epoll.h>

namespace OdinSight::System {

// Forward declare to avoid header loops
class EPollManager;

class EPollBinding {
  friend class EPollManager;

private:
  /** --- Private Type Aliases & Constants --- **/
  static constexpr uint64_t MAGIC_CONSTANT = 0x5459524553454355;
  using Handler                            = void (*)(void *context, uint32_t events);

  /** --- Members (State) --- **/
  uint64_t      m_instance_magic = MAGIC_CONSTANT;
  EPollManager *m_manager        = nullptr;
  int           m_fd             = -1;
  void         *m_ctx            = nullptr;
  Handler       m_on_event       = nullptr;
  uint32_t      m_event_mask     = 0;
  bool          m_active         = false;

public:
  /** --- Lifecycle --- **/
  EPollBinding(EPollManager *manager, int file_descriptor, void *ctx, Handler handler);
  ~EPollBinding();

  // Rule of Five: Move is allowed, Copy is deleted
  EPollBinding(EPollBinding &&other) noexcept;
  EPollBinding &operator=(EPollBinding &&other) noexcept;

  EPollBinding(const EPollBinding &)            = delete;
  EPollBinding &operator=(const EPollBinding &) = delete;

  /** --- Control API --- **/
  [[nodiscard]] bool subscribe(uint32_t events);
  [[nodiscard]] bool unsubscribe();

  /** --- Status Queries --- **/
  [[nodiscard]] bool isValid() const noexcept {
    return (m_instance_magic == MAGIC_CONSTANT) && (m_on_event != nullptr) && m_active;
  }

  [[nodiscard]] bool isActive() const noexcept { return m_active; }

  /** --- Dispatch Logic --- **/
  void dispatch(uint32_t incoming_events) const {
    // Trigger if requested bits or system error bits (HUP/ERR) are set
    const uint32_t critical_bits = incoming_events & (m_event_mask | EPOLLERR | EPOLLHUP);

    if (isValid() && critical_bits != 0U) {
      m_on_event(m_ctx, incoming_events);
    }
  }

private:
  /** --- Internal Helpers --- **/
  void invalidate();
};

} // namespace OdinSight::System
