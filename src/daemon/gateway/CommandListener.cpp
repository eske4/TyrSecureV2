#include "CommandListener.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <optional>
#include <print>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace OdinSight::Daemon::Control {

namespace sys    = OdinSight::System;
namespace common = OdinSight::Common;

using Error = Odin::Error;

using DaemonCommand = OdinSight::Common::DaemonCommand;
using CommadPacket  = OdinSight::Common::CommandPacket;

const std::string_view ctx = "CommandListener";

CommandListener::~CommandListener() { stop(); }

Odin::Result<std::unique_ptr<CommandListener>> CommandListener::create() {
  // 1. Define the internal defaults
  std::string defaultPath = Common::COMMAND_SOCKET_PATH;

  // 2. Instantiate via the private constructor
  auto instance = std::unique_ptr<CommandListener>(new CommandListener(std::move(defaultPath)));

  // 3. Safety Check: If for some reason 'new' failed (rare but possible)
  if (!instance) {
    return std::unexpected(
        Odin::Error::Logic(ctx, "create", "Failed to allocate memory for CommandListener"));
  }

  // 4. Wrap and return
  return instance;
}

Odin::Result<void> CommandListener::start() {
  stop();

  // 1. Create Socket
  int socket_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) { return std::unexpected(Error::System(ctx, "socket_create", errno)); }

  // 2. Wrap FD - Use Enrich if FD::adopt returns a Result/Error
  auto adopt_res = FD::adopt(socket_fd);
  if (!adopt_res) { return std::unexpected(Error::Enrich(ctx, "fd_adopt", adopt_res.error())); }
  m_serverFD = std::move(adopt_res.value());

  // 3. Prepare Abstract Socket Address
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  // The first byte is \0, making it an "abstract" socket
  if (m_path.size() + 1 > sizeof(addr.sun_path)) {
    closeServer();
    return std::unexpected(
        Error::Logic(ctx, "bind", "Abstract socket path exceeds sun_path limit"));
  }

  // Abstract socket: first byte is null, followed by name
  addr.sun_path[0] = '\0';
  std::memcpy(addr.sun_path + 1, m_path.c_str(), m_path.size());

  socklen_t addrLen = offsetof(struct sockaddr_un, sun_path) + 1 + m_path.size();

  // 4. Bind
  if (::bind(m_serverFD.get(), reinterpret_cast<const sockaddr*>(&addr), addrLen) < 0) {
    int err = errno;
    closeServer();
    return std::unexpected(Error::System(ctx, "bind", err));
  }

  // 5. Listen
  if (::listen(m_serverFD.get(), MAX_PENDING_CONNECTIONS) < 0) {
    int err = errno;
    closeServer();
    return std::unexpected(Error::System(ctx, "listen", err));
  }

  return {};
}

std::optional<CommadPacket> CommandListener::receivePacket(uint32_t events) {
  // 1. Check for Critical Errors on the Server Socket
  if ((events & (EPOLLERR | EPOLLHUP)) != 0U) { return std::nullopt; }

  if ((events & EPOLLIN) == 0U) { return std::nullopt; }

  // 1. ALWAYS accept the connection to clear the kernel backlog
  auto client_fd_res =
      FD::adopt(::accept4(m_serverFD.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
  if (!client_fd_res) { return std::nullopt; }

  auto& client_fd = client_fd_res.value();

  // 2. NOW check rate limiting. If too fast, the FD goes out of scope and closes.
  auto now = std::chrono::steady_clock::now();
  auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastAcceptTime).count();

  if (elapsed < COMMAND_COOLDOWN_MS) { return std::nullopt; }

  m_lastAcceptTime = now;

  // 3. Set small buffer to prevent memory-based DoS
  int smallBuf = sizeof(CommandPacket);
  ::setsockopt(client_fd.get(), SOL_SOCKET, SO_RCVBUF, &smallBuf, sizeof(smallBuf));

  CommandPacket packet{};

  ssize_t bytesReceived = ::recv(client_fd.get(), &packet, sizeof(packet), MSG_DONTWAIT);

  if (bytesReceived != static_cast<ssize_t>(sizeof(packet))) { return std::nullopt; }

  uint32_t rawCmd    = static_cast<uint32_t>(packet.command_id);
  uint32_t rawGameId = static_cast<uint32_t>(packet.game_id);

  if (rawGameId >= static_cast<uint32_t>(common::GameID::NUM_GAMES)) { return std::nullopt; }

  if (rawCmd >= static_cast<uint32_t>(common::DaemonCommand::NUM_COMMANDS)) { return std::nullopt; }

  return packet;
}

void CommandListener::stop() { closeServer(); }

void CommandListener::closeServer() {
  // Assuming sys::FD::release() or reset() handles the close() call
  m_serverFD.close();
}

} // namespace OdinSight::Daemon::Control
