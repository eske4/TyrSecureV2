#include "common/GameID.hpp"
#include <cstdint>

constexpr char SOCKET_PATH[] = "/run/ac_daemon.sock";
constexpr uint32_t MAGIC_VAL = 0x41434C58;

enum class Command : uint32_t {
        LAUNCH_GAME = 1
};

struct __attribute__((packed)) LaunchMessage {
        uint32_t magic;      // Must be MAGIC_VAL
        Command  cmd;        // Must be LAUNCH_GAME
        common::GameID game_id; // The path to the binary we want to wrap in eBPF
    };

