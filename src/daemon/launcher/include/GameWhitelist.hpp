#pragma once

#include "common/GameID.h"
#include <filesystem>
#include <optional>

struct GameEntry {
    std::filesystem::path binary;
    std::filesystem::path dataDir;
};

std::optional<GameEntry> findGame(const common::GameID &game_id);
