#include "CGroupService.hpp"
#include "CommandListener.hpp"
#include "EPollManager.hpp"
#include "IdentityService.hpp"
#include "Runner.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include "system/CGroup.hpp"
#include <iostream>

namespace Daemon   = OdinSight::Daemon;
namespace Launcher = Daemon::Launcher;
namespace Control  = Daemon::Control;
namespace sys      = OdinSight::System;
namespace common   = OdinSight::Common;

int main() {
  //
  auto epoll_manager = sys::EPollManager::create();
  auto runner        = Launcher::Runner::create();
  auto pCGroup       = sys::CGroup::create("daemon");

  auto &epoll_mgr = epoll_manager.value();
  auto &launcher  = runner.value();

  auto res = launcher->setup(common::GameID::AssaultCube, *pCGroup);
  if (!res) {
    std::clog << res.error().message() << std::endl;
  }
  auto res2 = launcher->start(epoll_mgr);
  if (!res2) {
    std::clog << res2.error().message() << std::endl;
  }

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
  auto daemon = Control::CommandListener::create();

  if (!daemon.value()->start()) {
    std::cerr << "Failed to start daemon. Are you root?" << std::endl;
    return 1;
  }

  daemon.value()->createEPollBinding(epoll_mgr);

  std::cout << "Daemon listening on abstract socket: \\0" << OdinSight::Common::COMMAND_SOCKET_PATH
            << std::endl;

  // 3. Simple Manual Epoll Loop (Since we aren't using your full EPollManager
  // yet)

  while (epoll_mgr.isRunning()) {
    // Poll with a timeout (e.g., 100ms) so the loop can check g_keep_running
    auto result = epoll_mgr.poll(100);
    if (!result) {

      std::clog << "Poll failed: " << result.error().message() << "\n";
    }
  }

  return 0;
} // namespace ACName::Daemon::Control
