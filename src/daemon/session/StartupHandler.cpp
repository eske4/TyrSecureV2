#include "StartupHandler.hpp"
#include "EPollManager.hpp"
#include "SyscallModule.hpp"
#include "common/Result.hpp"
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

using Error = Odin::Error;

namespace OdinSight::Daemon::Session {

StartupHandler::StartupHandler(Runner* runner, EbpfManager* ebpf_mgr, CommandListener* listener,
                               EPollManager* epoll_mgr, std::weak_ptr<CGroup> cg_parent)
    : m_listener(listener), m_runner(runner), m_ebpf_mgr(ebpf_mgr), m_epoll_mgr(epoll_mgr),
      m_cg_parent(std::move(cg_parent)) {}

Odin::Result<std::unique_ptr<IEPollListener>>
StartupHandler::create(Runner* runner, EbpfManager* ebpf_mgr, CommandListener* listener,
                       EPollManager* epoll_mgr, std::shared_ptr<CGroup> cg_parent) {
  if (runner == nullptr || ebpf_mgr == nullptr || listener == nullptr || cg_parent == nullptr) {
    return std::unexpected(Error::Logic(ctx, "create", "Invalid dependency pointers"));
  }

  return std::unique_ptr<StartupHandler>(
      new StartupHandler(runner, ebpf_mgr, listener, epoll_mgr, std::move(cg_parent)));
}

void StartupHandler::onEpollEvent(uint32_t events) {
  std::optional<CommandPacket> pkt = m_listener->receivePacket(events);
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
  int fd_to_remove = this->getFd().get();

  m_listener->stop();
  if (m_epoll_mgr->unsubscribe(fd_to_remove)) {}
}

std::optional<CommandPacket> StartupHandler::validatePacket(const CommandPacket& pkt) {
  bool isInvalidCmd =
      (pkt.command_id <= DaemonCommand::Unknown || pkt.command_id >= DaemonCommand::NUM_COMMANDS);

  bool isInvalidGame = (pkt.game_id <= GameID::Unknown || pkt.game_id >= GameID::NUM_GAMES);

  if (isInvalidCmd || isInvalidGame) {
    return std::nullopt; // Drop it
  }
  return pkt;
}

Odin::Result<void> StartupHandler::attachProtection() {
  // ----------------------------------------- //
  // Integrity check algorithm triggered here  //
  // ----------------------------------------- //

  if (m_ebpf_mgr == nullptr) {
    return std::unexpected(Error::Logic(ctx, "attach_protection", "eBPF Manager missing"));
  }

  if (auto res = setupModule(IEbpfModule::create<KMod::SyscallModule>()); !res) { return res; }

  return {};
}

Odin::Result<void> StartupHandler::launchGame() {
  if (m_runner == nullptr) {
    return std::unexpected(Error::Logic(ctx, "launch_game", "Runner missing"));
  }
  return m_runner->start();
}

Odin::Result<void> StartupHandler::prepareGame(const CommandPacket& pkt) {
  // 1. Check runner dependency
  if (m_runner == nullptr) {
    return std::unexpected(Error::Logic(ctx, "prepare_game", "Runner dependency missing"));
  }

  // 2. Attempt to promote weak_ptr to shared_ptr
  auto cg_ptr = m_cg_parent.lock();
  if (!cg_ptr) {
    // Return an error if the parent is gone (expired)
    return std::unexpected(Error::Logic(ctx, "prepare_game", "CGroup parent has expired"));
  }

  if (auto parent = cg_ptr->getParent(); parent != nullptr) {
    return m_runner->setup(pkt.game_id, parent);
  }
  return std::unexpected(Error::Logic(ctx, "prepare_game", "CGroup parent has expired"));

  // 3. Delegate to runner
}

Odin::Result<void> StartupHandler::setupModule(Odin::Result<std::unique_ptr<IEbpfModule>> mod_res) {
  if (!mod_res) { std::unexpected(Error::Enrich(ctx, "ebpf_create", mod_res.error())); }

  return m_ebpf_mgr->addModule(std::move(mod_res.value()));
}

} // namespace OdinSight::Daemon::Session
