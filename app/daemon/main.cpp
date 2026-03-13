#include "CGManager.hpp"
#include "GLauncher.hpp"
#include <fcntl.h>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>

using GLauncher = Launcher::GLauncher;

int main() {

    std::cout << "Remember to set game path inside app/daemon/main.cpp and edit data_path and binary path" << std::endl;

    sys::CGroup cgroup = sys::CGManager::create("Tyrsecure");

    const char* data_path = "/home/eske/Downloads/AssaultCube_v1.3.0.2_LockdownEdition_RC1/"; // Use something simple like 'ls' for testing
    const char* binary_path = "/home/eske/Downloads/AssaultCube_v1.3.0.2_LockdownEdition_RC1/bin_unix/linux_64_client"; // Use something simple like 'ls' for testing


    GLauncher launcher;
    launcher.setup(binary_path, data_path, cgroup);
    launcher.start();

    if (!launcher.isActive() && launcher.getGpid() == -1) {
        std::cerr << "Failed to launch in cgroup. Check dmesg or errno." << std::endl;
    } else {
        std::cout << "Child started with PID: " << launcher.getGpid() << " With the name: " << launcher.getSessionInfo()->game_name << ". The cgroup id is: " << launcher.getSessionInfo()->cg.getID() << std::endl;
    }

    std::cout << "\nPress ENTER to delete the cgroup and exit..." << std::endl;

    std::cout << "Remember to set game path inside app/daemon/main.cpp and edit data_path and binary path" << std::endl;


    std::cin.get(); 

    return 0;
}
