#pragma once

#include "system/CGroup.hpp"
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace OdinSight::Daemon::Launcher {

struct Context {
  using CGroup = OdinSight::System::CGroup;
  using FD     = OdinSight::System::FD;

  FD                       executable_fd;
  FD                       working_dir_fd;
  uid_t                    uid;
  gid_t                    gid;
  std::string              game_name;
  std::vector<std::string> envp;
  std::vector<std::string> argv;
};

} // namespace OdinSight::Daemon::Launcher
