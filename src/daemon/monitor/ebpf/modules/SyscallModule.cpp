#include "SyscallModule.hpp"
#include <iostream>

namespace ACName::Daemon::Monitor::Kernel::Modules {

SyscallModule::SyscallModule() {}
SyscallModule::~SyscallModule() {
  if (m_skel != nullptr) {
    print_test__destroy(m_skel);
  }
}

bool SyscallModule::open() {
  m_skel = print_test__open();
  return m_skel != nullptr;
}

bool SyscallModule::load(int shared_rb_fd) {
  // CRITICAL: Tell this module to use the shared Ring Buffer FD
  // instead of creating its own internal 'rb' map.
  if (shared_rb_fd >= 0) {
    bpf_map__reuse_fd(m_skel->maps.rb, shared_rb_fd);
  }

  return print_test__load(m_skel) == 0;
}

bool SyscallModule::attach() { return print_test__attach(m_skel) == 0; }

void SyscallModule::processEvent(const ebpf_event *event, size_t size) {
  // Logic to handle the specific event type for this module
  std::cout << "[" << getName() << "] Event Type: " << event->event_type
            << event->timestamp << std::endl;
}

} // namespace ACName::Daemon::Monitor::Kernel::Modules
