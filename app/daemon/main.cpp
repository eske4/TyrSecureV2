#include "CGService.hpp"
#include "IdentityProvider.hpp"
#include "GLauncher.hpp"
#include <fcntl.h>
#include <iostream>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>

using GLauncher = Launcher::GLauncher;

// Using constexpr to avoid "Magic Strings" and make paths easy to find
static constexpr std::string_view GAME_DATA_PATH = "/home/eske/Downloads/AssaultCube_v1.3.0.2_LockdownEdition_RC1/";
static constexpr std::string_view GAME_BINARY_PATH = "/home/eske/Downloads/AssaultCube_v1.3.0.2_LockdownEdition_RC1/bin_unix/linux_64_client";
static constexpr std::string_view CGROUP_NAME = "TyrSecure";

int main() {
    std::cout << "[INFO] Initializing TyrSecure Daemon..." << std::endl;

    // 1. Create CGroup (Handling [[nodiscard]])
    sys::CGroup cgroup = sys::CGService::create(CGROUP_NAME);
    if (cgroup.get_fd() < 0) {
        std::cerr << "[FATAL] Failed to create CGroup: " << CGROUP_NAME << std::endl;
        return EXIT_FAILURE;
    }

    // 2. Setup Launcher
    GLauncher launcher;
    if (!launcher.setup(GAME_BINARY_PATH, GAME_DATA_PATH, cgroup)) {
        std::cerr << "[ERROR] Launcher setup failed. Verify binary path, working directory, and permissions." << std::endl;
        return EXIT_FAILURE;
    }

    // 3. Start Process
    launcher.start();

    // 4. Verify Launch and Access Session Info Safely
    if (!launcher.isActive()) {
        std::cerr << "[FATAL] Process failed to transition to ACTIVE state." << std::endl;
        return EXIT_FAILURE;
    }

    // Check pointer before dereferencing
    if (const auto* info = launcher.getSessionInfo()) {
        std::cout << "[SUCCESS] Child started!" << std::endl;
        std::cout << "  - PID:       " << launcher.getGpid() << std::endl;
        std::cout << "  - Name:      " << info->game_name << std::endl;
        std::cout << "  - CGroup ID: " << info->cg.getID() << std::endl;
    }

    std::cout << "\n[WAIT] Press ENTER to kill the session, clean up CGroup, and exit..." << std::endl;
    
    // Reminder message moved to a single, logical spot
    std::cout << "(Note: Edit GAME_DATA_PATH and GAME_BINARY_PATH constants in main.cpp for different games)" << std::endl;

    std::cin.get(); 

    // CGroup destructor triggers the "Nuclear Kill" automatically here
    return EXIT_SUCCESS;
}
