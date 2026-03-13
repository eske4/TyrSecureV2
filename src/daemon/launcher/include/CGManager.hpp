#pragma once

#include <cstdint>
#include <string_view>
#include <sys/types.h>
#include "system/CGroup.hpp"

namespace sys {

class CGManager {
public:
    // Creates the cgroup directory and returns a directory FD
    // This FD is what you'll pass to clone_args.cgroup
    static sys::CGroup create(std::string_view name); 
    static uint64_t getID(const sys::FD &cg_fd);
    
    // Resource Limits (Stateless & Static)
    static bool setMemoryLimit(const sys::FD &cg_fd, size_t max_bytes);
    static bool setProcLimit(const sys::FD &cg_fd, int max_pids);
    static bool setCpuLimit(const sys::FD &cg_fd, std::string_view weight);
    
    // Required for clone3: must enable controllers in the parent 
    // before the child cgroup can enforce them.
    static bool enableSubtreeControllers(const sys::FD &parent_fd);

    static bool writeCG(const sys::FD &cg_fd, const std::string &file_name, std::string_view value);
};

}

