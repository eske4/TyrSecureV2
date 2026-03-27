#pragma once

#include "GameID.hpp"
#include <cstdint>

namespace OdinSight::Common {

enum class DaemonCommand : uint32_t { Unknown = 0, Launch, NUM_COMMANDS };

#pragma pack(push, 1)
struct CommandPacket {
  DaemonCommand command_id;
  GameID        game_id;
};
#pragma pack(pop)

// Centralize the socket path here too, so both sides use the same string
inline static constexpr char COMMAND_SOCKET_PATH[] = "os_hugin";

} // namespace OdinSight::Common
