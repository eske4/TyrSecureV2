#include "CommandListener.hpp"
#include "common/GameID.hpp"
#include "common/Protocol.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace ACName::Daemon::Control {

namespace sys    = ACName::System;
namespace common = ACName::Common;

CommandListener::CommandListener(std::string path, Validator validator, Handler handler)
    : m_path(std::move(path)), m_validator(validator ? std::move(validator) : defaultValidator),
      m_handler(handler ? std::move(handler) : defaultHandler) {}

CommandListener::~CommandListener() { stop(); }

bool CommandListener::start() {
  stop();

  // Resetting the managed FD
  m_serverFD.reset(::socket(AF_UNIX, SOCK_STREAM, 0));
  if (m_serverFD.get() < 0) {
    return false;
  }

  if (!setNonBlocking(m_serverFD)) {
    closeServer();
    return false;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;

  if (m_path.size() + 1 > sizeof(addr.sun_path)) {
    closeServer();
    return false;
  }

  // The first byte is \0, making it an "abstract" socket
  addr.sun_path[0] = '\0';

  std::memcpy(addr.sun_path + 1, m_path.c_str(), m_path.size());

  socklen_t addrLen = offsetof(struct sockaddr_un, sun_path) + 1 + m_path.size();

  const void     *raw_ptr    = &addr;
  const sockaddr *socket_ptr = static_cast<const sockaddr *>(raw_ptr);

  if (::bind(m_serverFD.get(), socket_ptr, addrLen) < 0) {
    closeServer();
    return false;
  }

  if (::listen(m_serverFD.get(), MAX_PENDING_CONNECTIONS) < 0) {
    closeServer();
    return false;
  }

  return true;
}

void CommandListener::handleEvents(uint32_t events) {
  // 1. Check for Critical Errors on the Server Socket
  if ((events & (EPOLLERR | EPOLLHUP)) != 0U) {
    // This usually means the socket was closed externally or a kernel error
    // occurred. In an anti-cheat, we should probably attempt to restart the
    // listener.
    start();
    return;
  }

  if ((events & EPOLLIN) == 0U) {
    return;
  }

  // Rate Limiting: Don't even accept if we just processed something.
  // This kills a root-level script's ability to "spam" the daemon.

  auto now = std::chrono::steady_clock::now();

  auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastAcceptTime).count();

  if (elapsed < COMMAND_COOLDOWN_MS) {
    // Just return; the kernel backlog will handle the wait.
    return;
  }

  m_lastAcceptTime = std::chrono::steady_clock::now();

  FD clientFD;
  clientFD.reset(::accept(m_serverFD.get(), nullptr, nullptr));
  if (clientFD.get() < 0) {
    return;
  }

  int smallBuf = sizeof(CommandPacket);
  ::setsockopt(clientFD.get(), SOL_SOCKET, SO_RCVBUF, &smallBuf, sizeof(smallBuf));

  processClient(clientFD);
}

void CommandListener::processClient(const FD &file_descriptor) {
  CommandPacket packet{};

  // 1. Receive the raw data from the socket
  ssize_t bytesReceived = ::recv(file_descriptor.get(), &packet, sizeof(packet), MSG_DONTWAIT);

  // 2. Validate that we received a full, complete packet
  if (bytesReceived == static_cast<ssize_t>(sizeof(packet))) {

    // 3. Convert fields from Network to Host byte order (Big Endian -> Little
    // Endian) We update the struct members directly so the callbacks receive
    // "clean" data.
    uint32_t rawCmd    = ::ntohl(static_cast<uint32_t>(packet.command_id));
    uint32_t rawGameId = ::ntohl(static_cast<uint32_t>(packet.game_id));

    // 4. Boundary safety check: Ensure the received IDs are within our enum
    // ranges
    if (rawGameId >= static_cast<uint32_t>(common::GameID::NUM_GAMES) ||
        rawCmd >= static_cast<uint32_t>(common::DaemonCommand::NUM_COMMANDS)) {
      // Optional: Log an "Invalid Packet Data" event here
      return;
    }

    // Write the converted values back into the packet
    packet.command_id = static_cast<common::DaemonCommand>(rawCmd);
    packet.game_id    = static_cast<common::GameID>(rawGameId);

    // 5. Generic Validation & Execution
    // We now pass the entire packet by reference as defined in your new header.
    if (m_validator && m_validator(packet)) {
      if (m_handler) {
        m_handler(packet);
      }
    }
  }
}

void CommandListener::stop() { closeServer(); }

void CommandListener::closeServer() {
  // Assuming sys::FD::release() or reset() handles the close() call
  m_serverFD.reset();
}

bool CommandListener::setNonBlocking(const sys::FD &file_descriptor) {
  int flags = ::fcntl(file_descriptor.get(), F_GETFL, 0);
  if (flags == -1) {
    return false;
  }
  return ::fcntl(file_descriptor.get(), F_SETFL, flags | O_NONBLOCK) == 0;
}

// In UnixCommandDaemon.hpp
bool CommandListener::createEPollBinding(sys::EPollManager *manager) {
  // Safety check:
  // 1. Manager must exist
  // 2. Server socket must be initialized (m_serverFD > 0)
  // 3. We shouldn't already have an active binding
  if (manager == nullptr || m_serverFD.get() < 0 || m_binding != nullptr) {
    return false;
  }

  // The lambda matches the signature expected by your EPollBinding
  auto on_event = [](void *context, uint32_t events) {
    auto *self = static_cast<CommandListener *>(context);
    if (self) {
      self->handleEvents(events);
    }
  };

  // Create the managed binding
  m_binding = std::make_unique<sys::EPollBinding>(manager, m_serverFD.get(), this, on_event);

  // Attempt to subscribe.
  // Note: Using Level Triggered (default) instead of EPOLLET
  // because we want the manager to keep poking us if we don't
  // drain the accept queue in one go.
  if (!m_binding->subscribe(EPOLLIN)) {
    m_binding.reset(); // Clean up on failure
    return false;
  }

  return true;
}

} // namespace ACName::Daemon::Control
