#include "IdentityService.hpp"
#include "common/Result.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
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

using Error = Odin::Error;

namespace OdinSight::System {
using Path = std::filesystem::path;

Odin::Result<uid_t> IdentityService::getUID() {
  std::ifstream loginInfo("/proc/self/loginuid");
  if (!loginInfo.is_open()) { return std::unexpected(Error::System(ctx, "open_loginuid", errno)); }

  std::string line;
  if (!std::getline(loginInfo, line)) {
    return std::unexpected(Error::Logic(ctx, "read_loginuid", "File empty or unreadable"));
  }

  // Initialize to "Poison" (Max/Unset)
  uid_t loginuid = std::numeric_limits<uid_t>::max();
  auto [ptr, ec] = std::from_chars(line.data(), line.data() + line.size(), loginuid);

  // 1. If parsing FAILED, return the error
  if (ec != std::errc()) {
    return std::unexpected(Error::Logic(ctx, "parse_uid", "Malformed UID in procfs"));
  }

  // 2. Check for Security: Unset (-1) OR Root (0)
  // We treat both as invalid for a secure user-space session.
  if (loginuid == static_cast<uid_t>(-1) || loginuid == 0) {
    return std::unexpected(Error::Logic(ctx, "validate_uid", "Identity is root or unset"));
  }

  // 3. SUCCESS path
  return loginuid;
}

// Example of the thread-safe, robust lookup
Odin::Result<gid_t> IdentityService::getGID(uid_t login_uid) {
  // 1. Setup the buffer for the reentrant call
  long   initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t safe_size = (initial_size <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(initial_size);
  safe_size        = std::clamp(safe_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(safe_size);
  struct passwd     pwd{};
  struct passwd*    result = nullptr;

  // 2. Call the reentrant system lookup
  int status = getpwuid_r(login_uid, &pwd, buffer.data(), buffer.size(), &result);

  // 3. Handle System Errors (e.g., ERANGE if buffer is too small)
  if (status != 0) { return std::unexpected(Error::System(ctx, "getpwuid_r", status)); }

  // 4. Handle "User Not Found" (status is 0, but result is null)
  if (result == nullptr) {
    return std::unexpected(Error::Logic(ctx, "find_user", "UID not found in system database"));
  }

  // 5. Security Check: Block Root GID (0)
  if (pwd.pw_gid == 0) {
    return std::unexpected(
        Error::Logic(ctx, "security_check", "Target user belongs to root group"));
  }
  return pwd.pw_gid;
}

Odin::Result<std::vector<std::string>> IdentityService::getUserEnvironment(uid_t uid) {
  struct passwd  pwd{};
  struct passwd* result = nullptr;

  long   initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t safe_size = (initial_size <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(initial_size);
  safe_size        = std::clamp(safe_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(safe_size);
  int               status = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

  // 1. Explicit Error Handling (No more silent empty returns)
  if (status != 0) { return std::unexpected(Error::System(ctx, "getpwuid_r_env", status)); }
  if (result == nullptr) {
    return std::unexpected(Error::Logic(ctx, "env_lookup", "UID does not exist"));
  }

  std::vector<std::string> env;

  // 2. Inherit Current Environment
  if (environ != nullptr) {
    for (char** current = environ; *current != nullptr; ++current) { env.emplace_back(*current); }
  }

  // 3. Helper for sanitization
  auto override_env = [&](std::string_view key, std::string_view value) {
    // Remove ANY existing instance of this key to prevent duplicates/spoofing
    std::string prefix = std::string(key) + "=";
    env.erase(std::remove_if(env.begin(), env.end(),
                             [&](const std::string& str) { return str.starts_with(prefix); }),
              env.end());

    // Add the verified ground-truth value
    env.push_back(prefix + std::string(value));
  };

  // 4. SECURITY: Strip malicious preloads and set safe paths
  override_env("LD_LIBRARY_PATH", "/usr/lib:/usr/lib32:/lib:/lib32");

  // 5. IDENTITY: Ground-truth from /etc/passwd
  override_env("USER", pwd.pw_name);
  override_env("LOGNAME", pwd.pw_name);
  override_env("HOME", pwd.pw_dir);
  override_env("SHELL", pwd.pw_shell);
  override_env("XDG_RUNTIME_DIR", "/run/user/" + std::to_string(uid));

  return env;
}

Odin::Result<std::string> IdentityService::getHomeDirectory(uid_t uid) {
  // 1. Handle Invalid UID early
  if (uid == static_cast<uid_t>(-1)) {
    return std::unexpected(Error::Logic(ctx, "get_home", "Invalid UID provided"));
  }

  struct passwd  pwd{};
  struct passwd* result;

  // 2. Buffer Management
  long   conf_size   = sysconf(_SC_GETPW_R_SIZE_MAX);
  size_t buffer_size = (conf_size <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(conf_size);
  buffer_size        = std::clamp(buffer_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(buffer_size);

  // 3. Query the system database
  int status = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

  // 4. Verification
  if (status != 0 || result == nullptr) {
    return std::unexpected(Error::System(ctx, "getpwuid_r_home", status));
  }

  if (result == nullptr) {
    return std::unexpected(Error::Logic(ctx, "home_lookup", "User not found"));
  }

  // 5. Final Sanity Check: Ensure the directory string isn't null or empty
  if (pwd.pw_dir == nullptr || pwd.pw_dir[0] == '\0') {
    return std::unexpected(Error::Logic(ctx, "home_missing", "Home directory field is empty"));
  }

  // Deep copy happens here before 'buffer' goes out of scope
  return std::string(pwd.pw_dir);
}

Odin::Result<Path> IdentityService::expandUserPath(const path& rawPath, uid_t uid) {
  if (rawPath.empty()) {
    return std::unexpected(Error::Logic(ctx, "expand_path", "Path is empty"));
  }

  std::string pathStr = rawPath.string();

  // Handle the tilde internally
  if (pathStr.starts_with('~')) {
    auto home = getHomeDirectory(uid);

    // Error Guard: Propagate failure immediately
    if (!home) { return std::unexpected(Error::Enrich(ctx, "tilde_expansion", home.error())); }

    // Construct the expanded path
    pathStr = (pathStr.length() == 1) ? *home : *home + pathStr.substr(1);
  }
  std::error_code err;
  auto            absPath = std::filesystem::absolute(pathStr, err);

  if (err) { return std::unexpected(Error::System(ctx, "fs_absolute", err.value())); }

  return absPath.lexically_normal();
}

void IdentityService::printEnvironment(const std::vector<std::string>& env, uid_t uid) {
  std::cout << "--- Synthesized Environment for UID " << uid << " ---\n";
  if (env.empty()) {
    std::cout << "[Empty or Failed to fetch]\n";
    return;
  }

  for (const auto& var : env) { std::cout << "  " << var << "\n"; }
  std::cout << "------------------------------------------" << std::endl;
}

} // namespace OdinSight::System
