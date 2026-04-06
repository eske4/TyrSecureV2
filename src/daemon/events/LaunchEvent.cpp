#include "LaunchEvent.hpp"
#include "EPollManager.hpp"
#include "SyscallModule.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include <optional>
#include <sys/epoll.h>

namespace Kernel = OdinSight::Daemon::Monitor::Kernel;
namespace Common = OdinSight::Common;
namespace KMod   = Kernel::Modules;
namespace System = OdinSight::System;

using CommandPacket  = Common::CommandPacket;
using GameID         = Common::GameID;
using DaemonCommand  = Common::DaemonCommand;
using IEbpfModule    = Kernel::IEbpfModule;
using IEPollListener = System::IEPollListener;

using Error        = Odin::Error;
using FD           = OdinSight::System::FD;
using EbpfModuleId = OdinSight::Daemon::Monitor::Kernel::EbpfModuleId;

namespace OdinSight::Daemon::Events {

LaunchEvent::LaunchEvent(OdinEngine& engine) : m_engine(engine) {}

Odin::Result<std::unique_ptr<System::IEPollListener>> LaunchEvent::create(OdinEngine& engine) {
  // 1. Allocate using nothrow to prevent exceptions
  auto* ptr = new (std::nothrow) LaunchEvent(engine);

  // 2. Explicit memory check
  if (ptr == nullptr) {
    return std::unexpected(
        Error::Logic(ctx, "create", "Failed to allocate memory for LaunchEvent"));
  }

  // 3. Wrap in unique_ptr and return as the Interface type
  // We use the pointer constructor here because std::make_unique
  // cannot access private constructors.
  return std::unique_ptr<System::IEPollListener>(ptr);
}

void LaunchEvent::onEpollEvent(uint32_t events) {
  auto*                        listener = m_engine.getListener();
  std::optional<CommandPacket> pkt      = listener->receivePacket(events);
  if (!pkt.has_value()) { return; }

  std::optional<CommandPacket> validated_pkt = validatePacket(pkt.value());

  if (!validated_pkt.has_value()) { return; }

  if (auto res = prepareGame(validated_pkt.value()); !res) {
    std::cerr << "[Error] Failed to prepare game environment: " << res.error().message()
              << std::endl;
    return;
  }

  if (auto res = attachProtection(); !res) {
    std::cerr << "[Error] Failed attaching eBPF protection: " << res.error().message() << std::endl;
    return;
  }

  if (auto res = launchGame(); !res) {
    std::cerr << "[Error] Failed to launch game process: " << res.error().message() << std::endl;
    return;
  }

  int   fd_to_remove = this->getFd().get();
  auto* epoll_mgr    = m_engine.getEPoll();

  listener->stop();

  if (epoll_mgr != nullptr) {
    if (auto res = epoll_mgr->unsubscribe(fd_to_remove); !res) {
      std::cerr << "[" << ctx << "] Warning: Unsubscribe failed for FD " << fd_to_remove << ": "
                << res.error().message() << std::endl;
    }
  }

  if (auto res = m_engine.switchToMonitoring(); !res) {
    std::cerr << "[" << ctx
              << "] CRITICAL: Failed to transition to monitoring: " << res.error().message()
              << std::endl;

    // Potential emergency shutdown or recovery logic here
    return;
  }
}

std::optional<CommandPacket> LaunchEvent::validatePacket(const CommandPacket& pkt) {
  bool isInvalidCmd =
      (pkt.command_id <= DaemonCommand::Unknown || pkt.command_id >= DaemonCommand::NUM_COMMANDS);

  bool isInvalidGame = (pkt.game_id <= GameID::Unknown || pkt.game_id >= GameID::NUM_GAMES);

  if (isInvalidCmd || isInvalidGame) {
    return std::nullopt; // Drop it
  }
  return pkt;
}

Odin::Result<void> LaunchEvent::attachProtection() {
  // ----------------------------------------- //
  // Integrity check algorithm triggered here  //
  // ----------------------------------------- //

  auto* ebpf_mgr = m_engine.getEbpf();
  if (ebpf_mgr == nullptr) {
    return std::unexpected(Error::Logic(ctx, "attach_protection", "eBPF Manager missing"));
  }

  if (auto res = setupModule(IEbpfModule::create<KMod::SyscallModule>()); !res) { return res; }

  return {};
}

Odin::Result<void> LaunchEvent::launchGame() {
  auto* runner = m_engine.getRunner();
  if (runner == nullptr) {
    return std::unexpected(Error::Logic(ctx, "launch_game", "Runner missing"));
  }
  return runner->start();
}

Odin::Result<void> LaunchEvent::prepareGame(const CommandPacket& pkt) {
  // 1. Check runner dependency
  auto* runner = m_engine.getRunner();
  if (runner == nullptr) {
    return std::unexpected(Error::Logic(ctx, "prepare_game", "Runner dependency missing"));
  }

  auto cg_parent = m_engine.getCGroup();
  // 2. Attempt to promote weak_ptr to shared_ptr
  if (!cg_parent) {
    // Return an error if the parent is gone (expired)
    return std::unexpected(Error::Logic(ctx, "prepare_game", "CGroup parent has expired"));
  }

  if (auto parent = cg_parent->getParent(); parent != nullptr) {
    return runner->setup(pkt.game_id);
  }
  return std::unexpected(Error::Logic(ctx, "prepare_game", "CGroup parent has expired"));

  // 3. Delegate to runner
}

Odin::Result<void> LaunchEvent::setupModule(Odin::Result<std::unique_ptr<IEbpfModule>> mod_res) {
  auto* ebpf_mgr = m_engine.getEbpf();

  if (ebpf_mgr == nullptr) {
    return std::unexpected(Error::Logic(ctx, "setup", "Manager missing"));
  }

  if (!mod_res) { return std::unexpected(Error::Enrich(ctx, "ebpf_create", mod_res.error())); }

  const EbpfModuleId mod_id = mod_res.value()->getId();

  auto add_res = ebpf_mgr->addModule(std::move(mod_res.value()));
  if (!add_res) { return std::unexpected(Error::Enrich(ctx, "ebpf_add", add_res.error())); }

  if (auto reg_res = m_engine.registerModule(mod_id); !reg_res) {
    // If registration fails (e.g. limit reached), we should remove it from kernel
    // immediately to stay in a consistent state.
    if (auto rem_res = ebpf_mgr->removeModule(mod_id); !rem_res) {
      std::cerr << "[" << ctx << "] CRITICAL: Registration failed AND failed to detach: "
                << rem_res.error().message() << std::endl;
    }
    return reg_res;
  }

  return {};
}

const System::FD& LaunchEvent::getFd() const {
  // 1. Declare the empty FD as static so it lives for the entire program life
  static const System::FD empty_fd = System::FD::empty();

  // 2. Get the listener from the engine
  auto* listener = m_engine.getListener();

  if (listener == nullptr) { return empty_fd; }

  // 3. Return the real FD by reference
  return listener->getFd();
}
} // namespace OdinSight::Daemon::Events
