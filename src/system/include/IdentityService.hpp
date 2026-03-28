#pragma once

#include <filesystem>
#include <string>
#include <sys/types.h>
#include <vector>

namespace OdinSight::System {

/**
 * @class IdentityService
 * @brief Provides system-level user and group identity lookups.
 */
class IdentityService {
public:
  using path        = std::filesystem::path;
  /** --- Lifecycle --- **/
  IdentityService() = default;

  /** --- User Identity Retrieval --- **/

  /**
   * @brief Retrieves the UID of the current process owner.
   * @return The system uid_t.
   */
  [[nodiscard]] static uid_t getUID();
  [[nodiscard]] static gid_t getGID(uid_t uid);

  /** --- Environment Management --- **/
  [[nodiscard]] static std::vector<std::string> getUserEnvironment(uid_t uid);
  [[nodiscard]] static path                     expandUserPath(const path &rawPath, uid_t uid);

  /**
   * @brief Debug utility to print the environment variables for a specific user.
   * @param env The environment vector to print.
   * @param uid The user ID associated with this environment.
   */
  static void printEnvironment(const std::vector<std::string> &env, uid_t uid);

private:
  [[nodiscard]] static std::string getHomeDirectory(uid_t uid);
};

} // namespace OdinSight::System
