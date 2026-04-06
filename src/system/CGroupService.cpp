#include "CGroupService.hpp"
#include "system/CGroup.hpp"

#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using Error  = Odin::Error;

namespace OdinSight::System {

Odin::Result<void> CGService::writeCG(const CGroup& cgroup, const std::string& file_name,
                                      std::string_view value) {
  // 1. Basic validation of the handle
  const auto& cgroup_fd = cgroup.getFD();
  if (!cgroup_fd.isValid()) {
    return std::unexpected(Error::Logic(ctx, "write_cg", "Invalid CGroup directory FD"));
  }

  if (file_name.empty()) {
    return std::unexpected(Error::Logic(ctx, "write_cg", "Filename cannot be empty"));
  }

  // 2. Open relative to the CGroup directory FD
  // We use your FD::openAt which likely uses RESOLVE_BENEATH for security.
  auto open_res = FD::openAt(cgroup_fd, file_name, O_WRONLY | O_CLOEXEC);

  if (!open_res) {
    // Propagate why we couldn't open the file (e.g., file_name doesn't exist)
    return std::unexpected(Error::Enrich(ctx, "open_cg_file", open_res.error()));
  }

  // 3. Perform the write syscall
  // We use the underlying FD from the expected object
  auto& file_fd = open_res.value();

  ssize_t bytes_written = ::write(file_fd.get(), value.data(), value.size());

  // 4. Validate the write result
  if (bytes_written < 0) {
    // Return the actual system error (e.g., EINVAL if the kernel dislikes the value)
    return std::unexpected(Error::System(ctx, "write_sys", errno));
  }

  if (static_cast<size_t>(bytes_written) != value.size()) {
    // Partial writes in CGroup virtual files are rare but technically errors
    return std::unexpected(
        Error::Logic(ctx, "write_partial", "Incomplete write to cgroup interface"));
  }

  return {}; // Success
}
// Resource Limits (Stateless & Static)
Odin::Result<void> CGService::setMemoryLimit(const CGroup& cgroup, size_t max_bytes) {
  return writeCG(cgroup, "memory.max", std::to_string(max_bytes));
}

Odin::Result<void> CGService::setProcLimit(const CGroup& cgroup, int max_pids) {
  return writeCG(cgroup, "pids.max", std::to_string(max_pids));
}

Odin::Result<void> CGService::setCpuLimit(const CGroup& cgroup, std::string_view weight) {
  // weight is usually 1-10000, default 100
  return writeCG(cgroup, "cpu.weight", weight);
}

Odin::Result<void> CGService::enableSubtreeControllers(const CGroup& parent_cgroup) {
  // Enable the most common controllers for children
  // Note: '+' prefix is required in subtree_control
  return writeCG(parent_cgroup, "cgroup.subtree_control", "+cpu +memory +pids");
}

Odin::Result<void> CGService::killProcs(const CGroup& cgroup) {
  return writeCG(cgroup, "cgroup.kill", "1");
}

} // namespace OdinSight::System
