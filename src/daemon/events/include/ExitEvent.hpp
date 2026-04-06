#pragma once

#include "EPollManager.hpp"
#include "IEbpfModule.hpp"
#include "OdinEngine.hpp"
#include "common/Protocol.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include <memory>

namespace OdinSight::Daemon::Events {

class ExitEvent : public System::IEPollListener {
  using FD            = System::FD;
  using CommandPacket = OdinSight::Common::CommandPacket;
  using IEbpfModule   = OdinSight::Daemon::Monitor::Kernel::IEbpfModule;

private:
  // CommandListener ref
  OdinEngine&                       m_engine;
  uint32_t                          m_events = EPOLLIN | EPOLLET;
  static constexpr std::string_view ctx      = "ExitEvent";

  explicit ExitEvent(OdinEngine& engine);

  [[nodiscard]] Odin::Result<void> deattachProtection();

public:
  ExitEvent(const ExitEvent&)            = delete;
  ExitEvent& operator=(const ExitEvent&) = delete;
  ExitEvent(ExitEvent&&)                 = delete;
  ExitEvent& operator=(ExitEvent&&)      = delete;

  ~ExitEvent() override = default;

  [[nodiscard]] static Odin::Result<std::unique_ptr<IEPollListener>> create(OdinEngine& engine);

  void onEpollEvent(uint32_t events) override;

  [[nodiscard]] uint32_t  getEvents() const override { return m_events; }
  [[nodiscard]] const FD& getFd() const override;
};
} // namespace OdinSight::Daemon::Events
