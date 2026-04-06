#pragma once

#include "common/GameID.hpp"
#include <filesystem>
#include <optional>

namespace OdinSight::Daemon::Launcher {

using GameID = OdinSight::Common::GameID;

struct GameEntry {
  std::filesystem::path binary;
  std::filesystem::path dataDir;
};

[[nodiscard]] std::optional<GameEntry> findGame(const GameID &game_id);

} // namespace OdinSight::Daemon::Launcher
