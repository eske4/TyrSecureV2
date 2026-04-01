#pragma once

#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include "common/Protocol.hpp"

#include <chrono>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <sys/epoll.h>
#include <system_error>

namespace OdinSight::Daemon::Control {

class CommandListener final {
public:
  /** --- Public Type Aliases --- **/
  using CommandPacket = OdinSight::Common::CommandPacket;
  using Handler =
      std::function<void(const CommandPacket &packet)>; // Change based on event system design

  template <typename T> using Result = std::expected<T, std::error_code>;

private:
  /** --- Private Type Aliases --- **/
  using FD           = OdinSight::System::FD;
  using EPollManager = OdinSight::System::EPollManager;
  using EPollBinding = OdinSight::System::EPollBinding;

  /** --- Constants --- **/
  static constexpr int MAX_PENDING_CONNECTIONS = 16;
  static constexpr int COMMAND_COOLDOWN_MS     = 1000;

  /** --- Members (State) --- **/
  std::string m_path;
  FD          m_serverFD = FD::empty();
  ;
  std::unique_ptr<EPollBinding>         m_binding;
  Handler                               m_handler;
  std::chrono::steady_clock::time_point m_lastAcceptTime{
      std::chrono::steady_clock::now() - std::chrono::milliseconds(COMMAND_COOLDOWN_MS)};

  /** --- Private Constructor (Factory Pattern) --- **/
  explicit CommandListener(std::string path, Handler handler)
      : m_path(std::move(path)), m_handler(std::move(handler)) {}

public:
  /** --- Lifecycle & Control --- **/
  ~CommandListener();

  // Rule of Five singleton ish
  CommandListener(const CommandListener &)            = delete;
  CommandListener &operator=(const CommandListener &) = delete;
  CommandListener(CommandListener &&)                 = delete;
  CommandListener &operator=(CommandListener &&)      = delete;

  static Result<std::unique_ptr<CommandListener>> create();
  Result<void>                                    start();
  void                                            stop();

  /** --- Network / Epoll Integration --- **/
  bool         createEPollBinding(EPollManager &manager);
  Result<void> setHandler(Handler handler);
  void         handleEvents(uint32_t events);

  [[nodiscard]] Result<int> getFd() const { return m_serverFD.get(); }

private:
  /** --- Internal Helpers --- **/
  void processClient(const FD &file_descriptor);
  void closeServer();
};

} // namespace OdinSight::Daemon::Control
