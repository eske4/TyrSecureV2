#include "CGService.hpp"
#include "system/CGroup.hpp"

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace sys {

sys::CGroup CGService::create(std::string_view name) {
    if (name.empty()) {
        return {};
    }

    // 1. Construct path (using full namespace for header/source safety)
    fs::path target_path = std::filesystem::path("/sys/fs/cgroup") / name;

    // 2. Create the directories
    std::error_code err_code;
    fs::create_directories(target_path, err_code);
    if (err_code) {
        return {};
    }

    // 3. Open the Directory FD
    sys::FD cg_fd(target_path.string(), O_RDONLY | O_DIRECTORY);
    if (!cg_fd.isValid()) {
        return {};
    }

    // 4. Use the helper function to get the ID
    uint64_t cg_id = getID(cg_fd);

    // 5. Assemble and return
    // Note: cg_fd is moved here, which is fine because getID only takes a const reference
    return sys::CGroup(
        std::string(name), 
        target_path, 
        std::move(cg_fd), 
        cg_id
    );
}

uint64_t CGService::getID(const sys::FD& cg_fd) {
    struct stat targetStat;
    if (!cg_fd.isValid() || ::fstat(cg_fd.get(), &targetStat) == -1){
        return 0;
    }

    return static_cast<uint64_t>(targetStat.st_ino);
}
  

bool CGService::writeCG(const sys::FD &cg_fd, const std::string& file_name, std::string_view value) {
    if (!cg_fd.isValid() || file_name.empty()) {
        return false;
    }

    // Open relative to directory FD
    int file_descriptor = ::openat(cg_fd.get(), file_name.c_str(), O_WRONLY | O_CLOEXEC);
    if (file_descriptor < 0){
        return false;

    }

    ssize_t bytes_written = ::write(file_descriptor, value.data(), value.size());
    ::close(file_descriptor);

    return bytes_written == static_cast<ssize_t>(value.size());
}

    // Resource Limits (Stateless & Static)
bool CGService::setMemoryLimit(const sys::FD& cg_fd, size_t max_bytes) {
    return writeCG(cg_fd, "memory.max", std::to_string(max_bytes));
}

bool CGService::setProcLimit(const sys::FD& cg_fd, int max_pids) {
    return writeCG(cg_fd, "pids.max", std::to_string(max_pids));
}

bool CGService::setCpuLimit(const sys::FD& cg_fd, std::string_view weight) {
    // weight is usually 1-10000, default 100
    return writeCG(cg_fd, "cpu.weight", weight);
}
    
bool CGService::enableSubtreeControllers(const sys::FD& parent_fd) {
    // Enable the most common controllers for children
    // Note: '+' prefix is required in subtree_control
    return writeCG(parent_fd, "cgroup.subtree_control", "+cpuset +cpu +io +memory +pids");
}
}
