#include "CGroupService.hpp"
#include "system/CGroup.hpp"

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace OdinSight::System {

CGroup CGService::create(std::string_view name) {
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
  FD cg_fd(target_path.string(), O_RDONLY | O_DIRECTORY);
  if (!cg_fd.isValid()) {
    return {};
  }

  // 4. Use the helper function to get the ID
  uint64_t cg_id = cg_fd.getID();

  // 5. Assemble and return
  // Note: cg_fd is moved here, which is fine because getID only takes a const
  // reference
  return CGroup(std::string(name), target_path, std::move(cg_fd), cg_id);
}

bool CGService::writeCG(const CGroup &cgroup, const std::string &file_name,
                        std::string_view value) {
  if (!cgroup.get_fd().isValid() || file_name.empty()) {
    return false;
  }

  // Open relative to directory FD
  FD file_descriptor;

  file_descriptor.reset(::openat(cgroup.get_fd().get(), file_name.c_str(), O_WRONLY | O_CLOEXEC));
  if (file_descriptor.get() < 0) {
    return false;
  }

  ssize_t bytes_written = ::write(file_descriptor.get(), value.data(), value.size());

  return bytes_written == static_cast<ssize_t>(value.size());
}

// Resource Limits (Stateless & Static)
bool CGService::setMemoryLimit(const CGroup &cgroup, size_t max_bytes) {
  return writeCG(cgroup, "memory.max", std::to_string(max_bytes));
}

bool CGService::setProcLimit(const CGroup &cgroup, int max_pids) {
  return writeCG(cgroup, "pids.max", std::to_string(max_pids));
}

bool CGService::setCpuLimit(const CGroup &cgroup, std::string_view weight) {
  // weight is usually 1-10000, default 100
  return writeCG(cgroup, "cpu.weight", weight);
}

bool CGService::enableSubtreeControllers(const CGroup &parent_cgroup) {
  // Enable the most common controllers for children
  // Note: '+' prefix is required in subtree_control
  return writeCG(parent_cgroup, "cgroup.subtree_control", "+cpuset +cpu +io +memory +pids");
}

bool CGService::killProcs(const CGroup &cgroup) { return writeCG(cgroup, "cgroup.kill", "1"); }

} // namespace OdinSight::System
