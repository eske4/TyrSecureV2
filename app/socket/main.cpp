#include "CGroupService.hpp"
#include "CommandListener.hpp"
#include "EPollManager.hpp"
#include "IdentityService.hpp"
#include "Runner.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include "system/CGroup.hpp"
#include <iostream>

namespace Control = OdinSight::Daemon::Control;
namespace sys     = OdinSight::System;
namespace common  = OdinSight::Common;

int main() {
  //
  auto                                epoll_manager = sys::EPollManager::create().value();
  sys::CGroup                         pCGroup       = sys::CGService::create("daemon");
  OdinSight::Daemon::Launcher::Runner runner;

  runner.setup(common::GameID::AssaultCube, pCGroup);
  runner.start(epoll_manager);

  // 1. Define logic outside the class (no clutter, just a lambda!)
  auto validator = [](const common::CommandPacket &packet) {
    std::cout << "[Validator] Checking Cmd: " << static_cast<int>(packet.command_id)
              << " Game: " << static_cast<int>(packet.game_id) << std::endl;
    return packet.command_id == common::DaemonCommand::Launch; // Only allow "Launch"
  };

  auto handler = [](const common::CommandPacket &packet) {
    std::cout << "[Handler] SUCCESS: Launching Game ID " << static_cast<int>(packet.game_id)
              << "..." << std::endl;
  };

  // 2. Initialize (Using the abstract path "ac_test_socket")
  Control::CommandListener daemon(common::COMMAND_SOCKET_PATH, validator, handler);

  if (!daemon.start()) {
    std::cerr << "Failed to start daemon. Are you root?" << std::endl;
    return 1;
  }

  daemon.createEPollBinding(epoll_manager);

  std::cout << "Daemon listening on abstract socket: \\0" << OdinSight::Common::COMMAND_SOCKET_PATH
            << std::endl;

  // 3. Simple Manual Epoll Loop (Since we aren't using your full EPollManager
  // yet)

  while (epoll_manager.isRunning()) {
    // Poll with a timeout (e.g., 100ms) so the loop can check g_keep_running
    auto result = epoll_manager.poll(100);
  }

  return 0;
} // namespace ACName::Daemon::Control
