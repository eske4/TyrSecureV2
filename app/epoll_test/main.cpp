#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "SyscallModule.hpp"
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace KMod   = OdinSight::Daemon::Monitor::Kernel::Modules;
namespace Kernel = OdinSight::Daemon::Monitor::Kernel;
namespace sys    = OdinSight::System;
int main() {

  auto ebpf_manager  = std::make_unique<Kernel::EbpfManager>();
  auto epoll_manager = sys::EPollManager::create().value();

  if (!ebpf_manager->start()) {
    return 1;
  }
  // 1. Add your modules
  auto mod = std::make_unique<KMod::SyscallModule>();

  if (!ebpf_manager->addModule(std::move(mod))) {
    std::cerr << "Failed to load/attach BPF module" << std::endl;
    return 1;
  }

  // 3. Setup the Epoll Binding
  if (!ebpf_manager->createEPollBinding(&epoll_manager)) {
    std::cerr << "Failed to create epoll binding" << std::endl;
    return 1;
  }

  while (true) {
    int events = epoll_manager.poll(100).value();
  }
}
