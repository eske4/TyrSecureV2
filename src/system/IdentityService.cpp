#include "IdentityService.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <iostream>
#include <limits>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

// Buffer and Clamp sizes
constexpr size_t DEFAULT_PWD_BUFFER_SIZE = 1024;
constexpr size_t MIN_PWD_BUFFER_SIZE     = 2048;
constexpr size_t MAX_PWD_BUFFER_SIZE     = 16384;

// Identity constants
constexpr gid_t ROOT_GID   = 0;
constexpr uid_t INVALID_ID = static_cast<uid_t>(-1);

// Performance hints
constexpr size_t INITIAL_ENV_RESERVE = 12;

namespace fs = std::filesystem;

namespace OdinSight::System {

uid_t IdentityService::getUID() {
  std::ifstream loginInfo("/proc/self/loginuid");
  if (!loginInfo) {
    return INVALID_ID;
  }

  if (!loginInfo.is_open()) {
    return INVALID_ID;
  }

  std::string line;
  if (std::getline(loginInfo, line)) {
    uid_t loginuid       = std::numeric_limits<uid_t>::max();
    auto [ptr, err_code] = std::from_chars(line.data(), line.data() + line.size(), loginuid);

    // CRITICAL: Use &&. Only return if parsing SUCCEEDED and is not -1.
    if (err_code == std::errc() && loginuid != std::numeric_limits<uid_t>::max()) {
      if (loginuid != 0) {

        return loginuid;
      }
    }
  }
  return INVALID_ID;
}

// Example of the thread-safe, robust lookup
gid_t IdentityService::getGID(uid_t login_uid) {
  struct passwd  pwd;
  struct passwd *result;

  long   initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t safe_size = (initial_size <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(initial_size);
  safe_size        = std::clamp(safe_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(safe_size);

  // getpwuid_r is reentrant and much harder to "hook" or corrupt via race
  // conditions
  int status = getpwuid_r(login_uid, &pwd, buffer.data(), buffer.size(), &result);

  if (status != 0 || result == nullptr) {
    // Log: "Identity lookup failed for UID X"
    return INVALID_ID;
  }

  if (pwd.pw_gid == ROOT_GID) {
    std::cerr << "[SECURITY] Attempted to fetch GID for root-level access. Blocked." << std::endl;
    return INVALID_ID;
  }

  return pwd.pw_gid;
}

std::vector<std::string> IdentityService::getUserEnvironment(uid_t uid) {
  struct passwd  pwd;
  struct passwd *result;

  long   initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t safe_size = (initial_size <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(initial_size);
  safe_size        = std::clamp(safe_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(safe_size);
  int               status = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

  if (status != 0 || result == nullptr) {
    return {};
  }

  std::vector<std::string> env;

  if (environ != nullptr) {
    for (char **current = environ; *current != nullptr; ++current) {
      env.push_back(std::string(*current));
    }
  }

  // 2. APPLY FORCE-OVERRIDES (Identity "Ground Truth")
  // ensuring the child process uses the correct UID-based identity.
  auto override_env = [&](const std::string &key, const std::string &value) {
    // Remove existing key if it exists in the inherited 'environ'
    env.erase(std::remove_if(env.begin(), env.end(),
                             [&](const std::string &str) {
                               return str.compare(0, key.length() + 1, key + "=") == 0;
                             }),
              env.end());

    // Add the verified version
    env.push_back(key + "=" + value);
  };

  std::string safeLibPath = "/usr/lib:/usr/lib32:/lib:/lib32";

  override_env("LD_LIBRARY_PATH", safeLibPath);

  // Critical Identity Overrides
  override_env("USER", pwd.pw_name);
  override_env("LOGNAME", pwd.pw_name);
  override_env("HOME", pwd.pw_dir);
  override_env("SHELL", pwd.pw_shell);
  override_env("XDG_RUNTIME_DIR", "/run/user/" + std::to_string(uid));

  return env;
}

std::string IdentityService::getHomeDirectory(uid_t uid) {
  // 1. Handle Invalid UID early
  if (uid == static_cast<uid_t>(-1)) {
    return "";
  }

  struct passwd  pwd;
  struct passwd *result;

  // 2. Determine the required buffer size
  long   str         = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t buffer_size = (str <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(str);
  // Clamp to your predefined constants for safety
  buffer_size        = std::clamp(buffer_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(buffer_size);

  // 3. Query the system database
  int status = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

  // 4. Verification
  if (status != 0 || result == nullptr) {
    // Log the error: getpwuid_r failed or user doesn't exist
    return "";
  }

  // 5. Explicitly copy the path out of the buffer
  // pwd.pw_dir is a pointer into 'buffer', which will be destroyed
  return std::string(pwd.pw_dir);
}

fs::path IdentityService::expandUserPath(const path &rawPath, uid_t uid) {
  std::string pathStr = rawPath.string();

  // Handle the tilde internally
  if (!pathStr.empty() && pathStr[0] == '~') {
    std::string home = getHomeDirectory(uid);
    if (!home.empty()) {
      // Replace '~' with home directory
      pathStr = (pathStr.length() == 1) ? home : home + pathStr.substr(1);
    }
  }

  // Return the absolute, normalized version directly
  return fs::absolute(pathStr).lexically_normal();
}

void IdentityService::printEnvironment(const std::vector<std::string> &env, uid_t uid) {
  std::cout << "--- Synthesized Environment for UID " << uid << " ---\n";
  if (env.empty()) {
    std::cout << "[Empty or Failed to fetch]\n";
    return;
  }

  for (const auto &var : env) {
    std::cout << "  " << var << "\n";
  }
  std::cout << "------------------------------------------" << std::endl;
}

} // namespace OdinSight::System
