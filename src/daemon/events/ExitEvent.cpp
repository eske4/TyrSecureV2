#include "ExitEvent.hpp"
#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "common/Result.hpp"
#include <print>

using Error = Odin::Error;

namespace OdinSight::Daemon::Events {

ExitEvent::ExitEvent(OdinEngine& engine) : m_engine(engine) {}

Odin::Result<std::unique_ptr<System::IEPollListener>> ExitEvent::create(OdinEngine& engine) {
  // 1. Allocate using nothrow to prevent exceptions
  auto* ptr = new (std::nothrow) ExitEvent(engine);

  // 2. Explicit memory check
  if (ptr == nullptr) {
    return std::unexpected(Error::Logic(ctx, "create", "Failed to allocate memory for ExitEvent"));
  }

  // 3. Wrap in unique_ptr and return as the Interface type
  // We use the pointer constructor here because std::make_unique
  // cannot access private constructors.
  return std::unique_ptr<System::IEPollListener>(ptr);
}

void ExitEvent::onEpollEvent(uint32_t events) {
  auto* runner = m_engine.getRunner();

  if (runner == nullptr) { return; }

  std::println("Game exit detected. Cleaning up protection environment...");

  runner->stop();

  if (auto res = deattachProtection(); !res) {
    std::cerr << "[" << ctx << "] Error during protection detach: " << res.error().message()
              << std::endl;
  }

  if (auto res = m_engine.switchToWaiting(); !res) {
    std::cerr << "[" << ctx
              << "] CRITICAL: Failed to transition to monitoring: " << res.error().message()
              << std::endl;

    // Potential emergency shutdown or recovery logic here
    return;
  }
}

Odin::Result<void> ExitEvent::deattachProtection() {
  auto* ebpf_mgr = m_engine.getEbpf();

  // Safety check: if there's no manager, we can't detach anything
  if (ebpf_mgr == nullptr) {
    return std::unexpected(Odin::Error::Logic(ctx, "deattach", "EbpfManager is null during exit"));
  }

  // 1. Loop through the registered modules and remove them from the kernel
  for (auto module : m_engine.getActiveProtections()) {
    if (auto res = ebpf_mgr->removeModule(module); !res) {
      std::cerr << "[" << ctx
                << "] WARNING: Failed to remove ebpf module: " << static_cast<int>(module) << "\n"
                << res.error().message() << std::endl;
    }
  }

  m_engine.clearModules();

  return {};
}

const System::FD& ExitEvent::getFd() const {
  // 1. Declare the empty FD as static so it lives for the entire program life
  static const System::FD empty_fd = System::FD::empty();

  // 2. Get the listener from the engine
  auto* runner = m_engine.getRunner();

  if (runner == nullptr) { return empty_fd; }

  // 3. Return the real FD by reference
  return runner->getFd();
}

} // namespace OdinSight::Daemon::Events
