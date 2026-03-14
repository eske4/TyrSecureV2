#pragma once

#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include "system/CGroup.hpp"

namespace Launcher {

struct LContext {
    sys::CGroup cg;
    sys::FD executable_fd;
    sys::FD working_dir_fd;
    uid_t uid = -1;
    gid_t gid = -1;
    std::string game_name;
    std::vector<std::string> envp;
    std::vector<std::string> argv;
};

}
