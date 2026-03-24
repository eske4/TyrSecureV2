#pragma once

#include "common/GameID.hpp"
#include <filesystem>
#include <optional>

namespace ACName::Daemon::Launcher {

using GameID = ACName::Common::GameID;

struct GameEntry {
  std::filesystem::path binary;
  std::filesystem::path dataDir;
};

std::optional<GameEntry> findGame(const GameID &game_id);

} // namespace ACName::Daemon::Launcher
