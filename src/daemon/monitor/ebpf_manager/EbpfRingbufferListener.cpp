#include "EbpfRingBufListener.hpp"
#include "system/FD.hpp"

using FD             = OdinSight::System::FD;
using IEPollListener = OdinSight::System::IEPollListener;

namespace OdinSight::Daemon::Monitor::Kernel {

EbpfRingBufListener::EbpfRingBufListener(EbpfManager& ebpf_mgr) : m_ebpf_mgr(ebpf_mgr) {}

Odin::Result<std::unique_ptr<IEPollListener>> EbpfRingBufListener::create(EbpfManager& ebpf_mgr) {
  // 1. Validation: Ensure the manager actually has a valid FD to watch
  const auto& file_descriptor = ebpf_mgr.getPollingFd();
  if (!file_descriptor.isValid()) {
    return std::unexpected(Odin::Error::Logic("EbpfRingBufListener", "create",
                                              "EbpfManager has no valid RingBuffer FD"));
  }

  auto listener =
      std::unique_ptr<EbpfRingBufListener>(new (std::nothrow) EbpfRingBufListener(ebpf_mgr));

  if (!listener) {
    return std::unexpected(Odin::Error::Logic("EbpfRingBufListener", "alloc",
                                              "Failed to allocate memory for listener"));
  }

  return listener;
}

void EbpfRingBufListener::onEpollEvent(uint32_t events) {
  // 1. Check for valid event types.
  // EPOLLIN: Data is available to read.
  // EPOLLERR/HUP: Something went wrong with the kernel buffer or the map was detached.
  if ((events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) {
    // 2. Trigger the manager to drain the ring buffer.
    // Since onEpollEvent returns void, we handle errors internally.
    if (auto res = m_ebpf_mgr.consume(); !res) {
      // Log the error using your system's error handling
      // Odin::Logger::error("Failed to consume eBPF data: {}", res.error().message());
    }
  }
}

const FD& EbpfRingBufListener::getFd() const { return m_ebpf_mgr.getPollingFd(); }
} // namespace OdinSight::Daemon::Monitor::Kernel
