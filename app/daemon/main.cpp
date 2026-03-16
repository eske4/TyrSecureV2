#include "CGService.hpp"
#include "GLauncher.hpp"
#include "common/GameID.hpp"
#include "LaunchRequestReceiver.hpp"
#include <csignal>
#include <iostream>
#include <string_view>

using GLauncher = Launcher::GLauncher;

static constexpr std::string_view CGROUP_NAME = "TyrSecure";

// Flag to control main loop
volatile std::sig_atomic_t gRunning = 1;

// Signal handler for Ctrl+C
void handle_signal(int) {
    std::cout << "\n[INFO] Ctrl+C detected. Shutting down..." << std::endl;
    gRunning = 0;
}

int main() {
    std::signal(SIGINT, handle_signal);

    std::cout << "[INFO] Initializing TyrSecure Daemon..." << std::endl;

    GLauncher launcher;
    LaunchRequestReceiver receiver;
    if (!receiver.start()) {
        std::cerr << "[ERROR] Failed to start LaunchRequestReceiver\n";
        return EXIT_FAILURE;
    }

    sys::CGroup cgroup = sys::CGService::create(CGROUP_NAME);
    if (cgroup.get_fd() < 0) {
        std::cerr << "[FATAL] Failed to create CGroup: " << CGROUP_NAME << std::endl;
        return EXIT_FAILURE;
    }

    while (gRunning) {
        common::GameID game = receiver.waitForGameID();
        if (!gRunning) break;  // exit immediately on Ctrl+C

        if (game == common::GameID::None) continue;

        std::cout << "[INFO] Launch request received for game: "
                  << static_cast<int>(game) << std::endl;

        if (!launcher.setup(game, cgroup)) {
            std::cerr << "[ERROR] Launcher setup failed. Verify binary path, working directory, and permissions." << std::endl;
            continue;
        }

        launcher.start();

        if (!launcher.isActive()) {
            std::cerr << "[FATAL] Process failed to transition to ACTIVE state." << std::endl;
            continue;
        }

        if (const auto* info = launcher.getSessionInfo()) {
            std::cout << "[SUCCESS] Child started!" << std::endl;
            std::cout << "  - PID:       " << launcher.getGpid() << std::endl;
            std::cout << "  - Name:      " << info->game_name << std::endl;
            std::cout << "  - CGroup ID: " << info->cg.getID() << std::endl;
        }
    }

    std::cout << "[INFO] TyrSecure Daemon stopped gracefully. Destructors cleaning up..." << std::endl;
    return EXIT_SUCCESS;
}

