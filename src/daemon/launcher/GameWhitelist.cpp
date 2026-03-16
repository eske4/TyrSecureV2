#include "GameWhitelist.hpp"
#include <unordered_map>

// Using an anonymous namespace keeps this map "private" to this file.
namespace {
    const std::unordered_map<common::GameID, GameEntry> g_whitelist = {
        { 
            common::GameID::AssaultCube, 
            { "/home/eske/Downloads/AssaultCube_v1.2.0.2/bin_unix/linux_64_client",
              "/home/eske/Downloads/AssaultCube_v1.2.0.2/" 
            } 
        },
        // Add more games here...
    };
}

std::optional<GameEntry> findGame(const common::GameID &game_id) {
    // We look up the game and check the iterator in one line
    if (auto search = g_whitelist.find(game_id); search != g_whitelist.end()) {
        return search->second;
    }
    return std::nullopt;
}

