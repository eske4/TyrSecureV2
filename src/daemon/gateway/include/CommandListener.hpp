#pragma once

#include "common/Protocol.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include <chrono>
#include <expected>
#include <memory>
#include <string>
#include <sys/epoll.h>
#include <system_error>

namespace OdinSight::Daemon::Control {

class CommandListener final {
public:
  /** --- Public Type Aliases --- **/
  using CommandPacket = OdinSight::Common::CommandPacket;

private:
  /** --- Private Type Aliases --- **/
  using FD = OdinSight::System::FD;

  /** --- Constants --- **/
  static constexpr int MAX_PENDING_CONNECTIONS = 16;
  static constexpr int COMMAND_COOLDOWN_MS     = 1000;

  /** --- Members (State) --- **/
  std::string                           m_path;
  FD                                    m_serverFD = FD::empty();
  std::chrono::steady_clock::time_point m_lastAcceptTime{
      std::chrono::steady_clock::now() - std::chrono::milliseconds(COMMAND_COOLDOWN_MS)};

  /** --- Private Constructor (Factory Pattern) --- **/
  explicit CommandListener(std::string path) : m_path(std::move(path)) {}

public:
  /** --- Lifecycle & Control --- **/
  ~CommandListener();

  // Rule of Five singleton ish
  CommandListener(const CommandListener&)            = delete;
  CommandListener& operator=(const CommandListener&) = delete;
  CommandListener(CommandListener&&)                 = delete;
  CommandListener& operator=(CommandListener&&)      = delete;

  [[nodiscard]] static Odin::Result<std::unique_ptr<CommandListener>> create();
  [[nodiscard]] Odin::Result<void>                                    start();
  void                                                                stop();

  /** --- Network / Epoll Integration --- **/
  [[nodiscard]] std::optional<CommandPacket> receivePacket(uint32_t events);
  [[nodiscard]] const FD&                    getFd() const { return m_serverFD; }

private:
  /** --- Internal Helpers --- **/
  void processClient(const FD& file_descriptor);
  void closeServer();
};

} // namespace OdinSight::Daemon::Control
