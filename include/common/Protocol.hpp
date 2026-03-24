#pragma once

#include "GameID.hpp"
#include <cstdint>

namespace ACName::Common {

enum class DaemonCommand : uint32_t { Launch = 1, NUM_COMMANDS };

#pragma pack(push, 1)
struct CommandPacket {
  DaemonCommand command_id;
  GameID game_id;
};
#pragma pack(pop)

// Centralize the socket path here too, so both sides use the same string
inline static constexpr char COMMAND_SOCKET_PATH[] = "ac_TyrSecure";

} // namespace ACName::Common
