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

namespace OdinSight::System {

uid_t IdentityService::getUID() {
  std::ifstream loginInfo("/proc/self/loginuid");
  if (!loginInfo) {
    return INVALID_ID;
  }

  std::string line;
  if (std::getline(loginInfo, line)) {
    uid_t loginuid       = std::numeric_limits<uid_t>::max();
    auto [ptr, err_code] = std::from_chars(line.data(), line.data() + line.size(), loginuid);

    // CRITICAL: Use &&. Only return if parsing SUCCEEDED and is not -1.
    if (err_code == std::errc() && loginuid != std::numeric_limits<uid_t>::max()) {
      return loginuid;
    }
  }
  return static_cast<uid_t>(-1);
}

// Example of the thread-safe, robust lookup
gid_t IdentityService::getGID(uid_t login_uid) {
  struct passwd  pwd;
  struct passwd *result;
  char           buffer[DEFAULT_PWD_BUFFER_SIZE];

  // getpwuid_r is reentrant and much harder to "hook" or corrupt via race
  // conditions
  int status = getpwuid_r(login_uid, &pwd, buffer, sizeof(buffer), &result);

  if (status == 0 && result != nullptr) {
    // Anti-cheat policy: We likely don't want to run sessions for UID 0
    if (pwd.pw_gid != ROOT_GID) {
      return pwd.pw_gid;
    }
  }
  return static_cast<gid_t>(-1);
}

std::vector<std::string> IdentityService::getUserEnvironment(uid_t uid) {
  struct passwd  pwd;
  struct passwd *result;

  long initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);

  // Clamp logic
  size_t safe_size = (initial_size <= 0) ? MIN_PWD_BUFFER_SIZE : static_cast<size_t>(initial_size);
  safe_size        = std::clamp(safe_size, MIN_PWD_BUFFER_SIZE, MAX_PWD_BUFFER_SIZE);

  std::vector<char> buffer(safe_size);

  int status = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

  if (status != 0 || result == nullptr) {
    return {};
  }

  std::vector<std::string> env;
  env.reserve(INITIAL_ENV_RESERVE);

  // Note: pwd.pw_name etc. point to addresses INSIDE your 'buffer' vector.
  // std::string() copies that data out before the buffer goes out of scope.
  env.push_back("USER=" + std::string(pwd.pw_name));
  env.push_back("HOME=" + std::string(pwd.pw_dir));
  env.push_back("SHELL=" + std::string(pwd.pw_shell));
  env.push_back("LOGNAME=" + std::string(pwd.pw_name));

  env.push_back("XDG_RUNTIME_DIR=/run/user/" + std::to_string(uid));
  env.push_back("PATH=/usr/local/bin:/usr/bin:/bin");
  env.push_back("XDG_DATA_DIRS=/usr/local/share:/usr/share");

  auto inherit_env = [&](const char *var) {
    if (const char *val = getenv(var)) {
      env.push_back(std::string(var) + "=" + std::string(val));
    }
  };

  inherit_env("DISPLAY");
  inherit_env("WAYLAND_DISPLAY");
  inherit_env("XAUTHORITY");

  return env;
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
