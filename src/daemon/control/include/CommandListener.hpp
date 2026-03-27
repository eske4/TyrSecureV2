#pragma once

#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include "common/Protocol.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <sys/epoll.h>

namespace OdinSight::Daemon::Control {

class CommandListener {
public:
  /** --- Public Type Aliases --- **/
  using CommandPacket = OdinSight::Common::CommandPacket;
  using Validator     = std::function<bool(const CommandPacket &packet)>;
  using Handler       = std::function<void(const CommandPacket &packet)>;

private:
  /** --- Private Type Aliases --- **/
  using FD           = OdinSight::System::FD;
  using EPollManager = OdinSight::System::EPollManager;
  using EPollBinding = OdinSight::System::EPollBinding;

  /** --- Constants --- **/
  static constexpr int MAX_PENDING_CONNECTIONS = 16;
  static constexpr int COMMAND_COOLDOWN_MS     = 1000;

  /** --- Members (State) --- **/
  std::string                           m_path;
  Validator                             m_validator;
  Handler                               m_handler;
  FD                                    m_serverFD;
  std::unique_ptr<EPollBinding>         m_binding;
  std::chrono::steady_clock::time_point m_lastAcceptTime{
      std::chrono::steady_clock::now() - std::chrono::milliseconds(COMMAND_COOLDOWN_MS)};

public:
  /** --- Lifecycle & Control --- **/
  explicit CommandListener(std::string path, Validator validator = nullptr,
                           Handler handler = nullptr);
  ~CommandListener();

  // Rule of Three (Deleted)
  CommandListener(const CommandListener &)            = delete;
  CommandListener &operator=(const CommandListener &) = delete;

  bool start();
  void stop();

  /** --- Network / Epoll Integration --- **/
  bool createEPollBinding(EPollManager *manager);
  void handleEvents(uint32_t events);

  [[nodiscard]] int getFd() const { return m_serverFD; }

private:
  /** --- Internal Helpers --- **/
  void processClient(const FD &file_descriptor);
  void closeServer();

  static bool setNonBlocking(const FD &file_descriptor);
  static bool defaultValidator(const CommandPacket &packet) { return true; }
  static void defaultHandler(const CommandPacket &packet) {}
};

} // namespace OdinSight::Daemon::Control
