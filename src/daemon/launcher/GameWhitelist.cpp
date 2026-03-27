#include "GameWhitelist.hpp"
#include "common/GameID.hpp"
#include <unordered_map>

// Using an anonymous namespace keeps this map "private" to this file.
namespace {

using OdinSight::Daemon::Launcher::GameEntry;
using GameID = OdinSight::Common::GameID;

const std::unordered_map<GameID, GameEntry> &getWhitelist() {
  static const std::unordered_map<GameID, GameEntry> whitelist = {
      {GameID::AssaultCube,
       {"/home/eske/Downloads/AssaultCube_v1.3.0.2_LockdownEdition_RC1/"
        "bin_unix/linux_64_client",
        "/home/eske/Downloads/AssaultCube_v1.3.0.2_LockdownEdition_RC1/"}},
      // Add games here
  };
  return whitelist;
}

} // namespace

namespace OdinSight::Daemon::Launcher {

std::optional<GameEntry> findGame(const GameID &game_id) {
  const auto &whitelist = getWhitelist();
  auto        iterator  = whitelist.find(game_id);

  if (iterator != whitelist.end()) {
    return iterator->second;
  }
  return std::nullopt;
}

} // namespace OdinSight::Daemon::Launcher
