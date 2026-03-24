#pragma once

#include "system/CGroup.hpp"
#include <string_view>
#include <sys/types.h>

namespace ACName::System {

class CGService {
public:
  // Creates the cgroup directory and returns a directory FD
  // This FD is what you'll pass to clone_args.cgroup
  [[nodiscard]] static CGroup create(std::string_view name);
  [[nodiscard]] static bool   killProcs(const CGroup &cgroup);

  // Resource Limits (Stateless & Static)
  [[nodiscard]] static bool setMemoryLimit(const CGroup &cgroup, size_t max_bytes);
  [[nodiscard]] static bool setProcLimit(const CGroup &cgroup, int max_pids);
  [[nodiscard]] static bool setCpuLimit(const CGroup &cgroup, std::string_view weight);

  // Required for clone3: must enable controllers in the parent
  // before the child cgroup can enforce them.
  [[nodiscard]] static bool enableSubtreeControllers(const CGroup &parent_cgroup);
  [[nodiscard]] static bool writeCG(const CGroup &cgroup, const std::string &file_name,
                                    std::string_view value);
};

} // namespace ACName::System
