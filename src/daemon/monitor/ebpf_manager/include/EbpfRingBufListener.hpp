#pragma once

#include "EPollManager.hpp"
#include "EbpfManager.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include <memory>

namespace OdinSight::Daemon::Monitor::Kernel {

class EbpfRingBufListener : public System::IEPollListener {
  using FD           = System::FD;
  using EPollManager = System::EPollManager;

private:
  EbpfManager&                      m_ebpf_mgr;
  uint32_t                          m_events = EPOLLIN | EPOLLET;
  static constexpr std::string_view name     = "EbpfRingbufferChannel";

  explicit EbpfRingBufListener(EbpfManager& ebpf_mgr);

public:
  EbpfRingBufListener(EbpfRingBufListener&&)                 = delete;
  EbpfRingBufListener(const EbpfRingBufListener&)            = delete;
  EbpfRingBufListener& operator=(EbpfRingBufListener&&)      = delete;
  EbpfRingBufListener& operator=(const EbpfRingBufListener&) = delete;

  ~EbpfRingBufListener() override = default;

  void onEpollEvent(uint32_t events) override;
  static Odin::Result<std::unique_ptr<System::IEPollListener>> create(EbpfManager& ebpf_mgr);

  [[nodiscard]] uint32_t  getEvents() const override { return m_events; }
  [[nodiscard]] const FD& getFd() const override;
};
} // namespace OdinSight::Daemon::Monitor::Kernel
