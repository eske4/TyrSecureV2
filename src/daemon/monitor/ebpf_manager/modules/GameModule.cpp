#include "GameModule.hpp"
#include <iostream>
#include <unistd.h>

namespace OdinSight::Daemon::Monitor::Kernel::Modules {

using Error  = Odin::Error;
using Result = Odin::Result<void>;

static constexpr std::string_view ctx = "GameModule";

// Constructor body (initialization of m_skel, etc.)

Odin::Result<void> GameModule::open() {
  m_skel.reset(game_protection__open());
  if (!m_skel) {
    // Return the specific reason open failed (e.g., file not found)
    return std::unexpected(Error::System(ctx, "daemon_hardener__open", errno));
  }

  uint32_t current_pid = static_cast<uint32_t>(::getpid());

  m_skel->rodata->TARGET_CGROUP = m_cg_id;
  m_skel->rodata->DAEMON_PID    = current_pid;

  std::cout << "Daemon pid in game protection is: " << current_pid << std::endl;

  std::cout << "The cgroup id for game protection is: " << m_cg_id << std::endl;
  return {}; // Success
}

Odin::Result<void> GameModule::load(int shared_rb_fd) {
  if (!m_skel) { return std::unexpected(Error::Logic(ctx, "load", "Skeleton not opened")); }

  // CRITICAL: Tell this module to use the shared Ring Buffer FD
  // instead of creating its own internal 'rb' map.
  if (shared_rb_fd >= 0) {
    if (int err = bpf_map__reuse_fd(m_skel->maps.rb, shared_rb_fd); err < 0) {
      return std::unexpected(Error::System(ctx, "bpf_map__reuse_fd", -err));
    }
  }

  // 2. Load into Kernel
  if (int err = game_protection__load(m_skel.get()); err < 0) {
    return std::unexpected(Error::System(ctx, "daemon_hardener__load", -err));
  }

  return {};
}

Odin::Result<void> GameModule::attach() {
  if (!m_skel) { return std::unexpected(Error::Logic(ctx, "attach", "Skeleton not loaded")); }

  if (int err = game_protection__attach(m_skel.get()); err < 0) {
    return std::unexpected(Error::System(ctx, "daemon_hardener__attach", -err));
  }

  return {}; // Success
}

void GameModule::processEvent(const ebpf_event* event, size_t size) {
  // Logic to handle the specific event type for this module
  std::cout << "[" << getName() << "] Event Type: " << event->event_type << event->timestamp
            << std::endl;
}

} // namespace OdinSight::Daemon::Monitor::Kernel::Modules
