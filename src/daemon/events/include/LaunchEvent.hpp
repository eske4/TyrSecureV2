#pragma once

#include "EPollManager.hpp"
#include "IEbpfModule.hpp"
#include "OdinEngine.hpp"
#include "common/Protocol.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include <memory>
#include <optional>

namespace OdinSight::Daemon::Events {

class LaunchEvent : public System::IEPollListener {
  using FD            = System::FD;
  using CommandPacket = OdinSight::Common::CommandPacket;
  using IEbpfModule   = OdinSight::Daemon::Monitor::Kernel::IEbpfModule;

private:
  // CommandListener ref
  OdinEngine&                       m_engine;
  uint32_t                          m_events = EPOLLIN | EPOLLET;
  static constexpr std::string_view ctx      = "LaunchEvent";

  explicit LaunchEvent(OdinEngine& engine);

  [[nodiscard]] static std::optional<CommandPacket> validatePacket(const CommandPacket& pkt);
  [[nodiscard]] Odin::Result<void>                  prepareGame(const CommandPacket& pkt);
  [[nodiscard]] Odin::Result<void>                  attachProtection();
  [[nodiscard]] Odin::Result<void>                  launchGame();
  [[nodiscard]] Odin::Result<void> setupModule(Odin::Result<std::unique_ptr<IEbpfModule>> mod_res);

public:
  LaunchEvent(const LaunchEvent&)            = delete;
  LaunchEvent& operator=(const LaunchEvent&) = delete;
  LaunchEvent(LaunchEvent&&)                 = delete;
  LaunchEvent& operator=(LaunchEvent&&)      = delete;

  ~LaunchEvent() override = default;

  [[nodiscard]] static Odin::Result<std::unique_ptr<IEPollListener>> create(OdinEngine& engine);

  void onEpollEvent(uint32_t events) override;

  [[nodiscard]] uint32_t getEvents() const override { return m_events; }

  [[nodiscard]] const FD& getFd() const override;
};
} // namespace OdinSight::Daemon::Events
