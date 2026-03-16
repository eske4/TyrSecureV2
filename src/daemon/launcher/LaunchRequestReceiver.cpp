#include "LaunchRequestReceiver.hpp"
#include "common/local_protocol.hpp"
#include <cstdio>
#include <ostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>

LaunchRequestReceiver::LaunchRequestReceiver() {
    // No-op: handled by start()
}

LaunchRequestReceiver::~LaunchRequestReceiver() {
    unlink(SOCKET_PATH);
}

bool LaunchRequestReceiver::start() {
    // 1. If a socket file already exists (from a crash), remove it
    unlink(SOCKET_PATH);

    // 2. Create the Unix Domain Socket (Sequential Stream)
    int new_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    server_fd.reset(new_server_fd);
    if (!server_fd.isValid()) {
        perror("[ERROR] Failed to create socket");
        return false;
    }

    // 3. Define the address
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // 4. Bind the socket to the path
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("[ERROR] Failed to bind socket");
        return false;
    }

    // 5. Start listening (Backlog of 10 is plenty for this)
    if (listen(server_fd.get(), 10) == -1) {
        perror("[ERROR] Failed to listen on socket");
        return false;
    }

    return true;
}

common::GameID LaunchRequestReceiver::waitForGameID() {
    // This blocks (stalls) the thread until a connection arrives
    int client_fd = accept(server_fd.get(), nullptr, nullptr);
    if (client_fd == -1) {
        return common::GameID::None;
    }

    // Prepare the buffer
    LaunchMessage msg;
    
    // Read the exact size of our protocol struct. 
    // MSG_WAITALL ensures we don't get a "half-finished" message.
    ssize_t bytes = recv(client_fd, &msg, sizeof(msg), MSG_WAITALL);
    
    // We got what we needed, close the client connection immediately
    ::close(client_fd);

    // Validate the message "Signature"
    if (bytes == sizeof(msg) && msg.magic == MAGIC_VAL) {
        if (msg.cmd == Command::LAUNCH_GAME) {
            return msg.game_id;
        }
    }

    // If it wasn't a valid request, return None so main loop can skip it
    return common::GameID::None;
}
