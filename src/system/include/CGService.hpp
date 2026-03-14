#pragma once

#include <cstdint>
#include <string_view>
#include <sys/types.h>
#include "system/CGroup.hpp"

namespace sys {

class CGService {
public:
    // Creates the cgroup directory and returns a directory FD
    // This FD is what you'll pass to clone_args.cgroup
    [[nodiscard]] static sys::CGroup create(std::string_view name); 
    [[nodiscard]] static uint64_t getID(const sys::FD &cg_fd);
    
    // Resource Limits (Stateless & Static)
    [[nodiscard]] static bool setMemoryLimit(const sys::FD &cg_fd, size_t max_bytes);
    [[nodiscard]] static bool setProcLimit(const sys::FD &cg_fd, int max_pids);
    [[nodiscard]] static bool setCpuLimit(const sys::FD &cg_fd, std::string_view weight);
    
    // Required for clone3: must enable controllers in the parent 
    // before the child cgroup can enforce them.
    [[nodiscard]] static bool enableSubtreeControllers(const sys::FD &parent_fd);
    [[nodiscard]] static bool writeCG(const sys::FD &cg_fd, const std::string &file_name, std::string_view value);
};

}

