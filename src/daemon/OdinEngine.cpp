#include "OdinEngine.hpp"
#include "EPollManager.hpp"
#include "EbpfRingBufListener.hpp"
#include "ExitEvent.hpp"
#include "LaunchEvent.hpp"
#include "common/Result.hpp"
#include <print>

namespace OdinSight::Daemon {

using LaunchEvent         = OdinSight::Daemon::Events::LaunchEvent;
using ExitEvent           = OdinSight::Daemon::Events::ExitEvent;
using EbpfRingBufListener = Monitor::Kernel::EbpfRingBufListener;

using EbpfModuleId = OdinSight::Daemon::Monitor::Kernel::EbpfModuleId;

using Error = Odin::Error;

Odin::Result<OdinEngine> OdinEngine::create(std::shared_ptr<CGroup> parent_cg) {
  // 1. Construct the engine (calls private OdinEngine())
  OdinEngine engine;

  auto epoll_res = EPollManager::create();
  if (!epoll_res) { return std::unexpected(Error::Enrich(ctx, "create_epoll", epoll_res.error())); }

  // 2. Setup Ebpf }

  auto ebpf_res = EbpfManager::create();

  if (!ebpf_res) { return std::unexpected(Error::Enrich(ctx, "create_ebpf", ebpf_res.error())); }

  auto cg_res = CGroup::createAt(parent_cg, "daemon");
  if (!cg_res) { return std::unexpected(Error::Enrich(ctx, "create_cgroup", cg_res.error())); }

  auto runner_res = Runner::create();
  if (!runner_res) {
    return std::unexpected(Error::Enrich(ctx, "create_runner", runner_res.error()));
  }

  auto listener_res = CommandListener::create();
  if (!listener_res) {
    return std::unexpected(Error::Enrich(ctx, "create_listener", listener_res.error()));
  }

  engine.m_epoll_mgr = std::move(epoll_res.value());
  engine.m_ebpf_mgr  = std::move(ebpf_res.value());
  engine.m_cgroup    = std::move(cg_res.value());
  engine.m_runner    = std::move(runner_res.value());
  engine.m_listener  = std::move(listener_res.value());

  engine.m_loadedProtectionModules.reserve(MODULE_COUNT);

  return std::move(engine);
}

Odin::Result<void> OdinEngine::initializeManagers() {
  if (m_listener == nullptr) {
    return std::unexpected(Error::Logic(ctx, "init_managers", "Listener not initialized"));
  }

  if (auto res = m_listener->start(); !res) {
    return std::unexpected(Error::Enrich(ctx, "start_listener", res.error()));
  }

  return {};
}

Odin::Result<void> OdinEngine::initializeListeners() {
  auto rb_listener_res = EbpfRingBufListener::create(*m_ebpf_mgr);
  if (!rb_listener_res) {
    return std::unexpected(Error::Enrich(ctx, "create_rb_listener", rb_listener_res.error()));
  }

  if (auto res = m_epoll_mgr->subscribe(std::move(rb_listener_res.value())); !res) {
    return std::unexpected(Error::Enrich(ctx, "subscribe_rb_listener", res.error()));
  }

  auto wait_state_res = switchToWaiting();

  if (!wait_state_res) { return std::unexpected(wait_state_res.error()); }

  return {};
}

Odin::Result<void> OdinEngine::init() {
  if (auto res = initializeManagers(); !res) { return res; }
  if (auto res = initializeListeners(); !res) { return res; }
  return {};
}

Odin::Result<void> OdinEngine::switchToMonitoring() {
  std::println("Switching to monitor mode");
  auto exit_event_res = ExitEvent::create(*this);

  if (!exit_event_res) {
    return std::unexpected(Error::Enrich(ctx, "create_exit_event", exit_event_res.error()));
  }

  if (auto res = m_epoll_mgr->subscribe(std::move(*exit_event_res)); !res) {
    return std::unexpected(Error::Enrich(ctx, "subscribe_exit_event", res.error()));
  }

  return {};
}

Odin::Result<void> OdinEngine::switchToWaiting() {
  std::println("Switching to waiting state");
  if (m_listener == nullptr) {
    return std::unexpected(Error::Logic(ctx, "Checking listener", "CommandListener is missing"));
  }

  if (auto res = m_listener->start(); !res) {
    return std::unexpected(Error::Enrich(ctx, "initialize socket", res.error()));
  }

  auto startup_res = LaunchEvent::create(*this);

  if (!startup_res) {
    return std::unexpected(Error::Enrich(ctx, "create_launch_event", startup_res.error()));
  }

  if (auto res = m_epoll_mgr->subscribe(std::move(*startup_res)); !res) {
    return std::unexpected(Error::Enrich(ctx, "subscribe_startup", res.error()));
  }

  return {};
}

Odin::Result<void> OdinEngine::run() {
  if (!m_epoll_mgr) { return std::unexpected(Error::Logic(ctx, "run", "EPollManager missing")); }

  while (m_epoll_mgr->isRunning()) {
    if (auto res = m_epoll_mgr->poll(100); !res) {
      return std::unexpected(Error::Enrich(ctx, "poll_loop", res.error()));
    }
  }
  return {};
}

Odin::Result<void> OdinEngine::registerModule(EbpfModuleId mod_id) {
  if (m_loadedProtectionModules.size() >= MODULE_COUNT) {
    return std::unexpected(Error::Logic(ctx, "register", "Module limit reached"));
  }
  m_loadedProtectionModules.push_back(mod_id);
  return {};
}

// This triggers a 'move' into the Result wrapper
} // namespace OdinSight::Daemon
