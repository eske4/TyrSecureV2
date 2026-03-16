#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include "common/local_protocol.hpp"

int main() {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect");
        return 1;
    }

    LaunchMessage msg{};
    msg.magic = MAGIC_VAL;
    msg.cmd = Command::LAUNCH_GAME;
    msg.game_id = common::GameID::AssaultCube;

    send(fd, &msg, sizeof(msg), 0);

    close(fd);

    std::cout << "Launch request sent\n";
}
