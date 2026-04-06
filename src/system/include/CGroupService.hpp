#pragma once

#include "common/Result.hpp"
#include "system/CGroup.hpp"
#include <string_view>
#include <sys/types.h>

namespace OdinSight::System {

class CGService final {
public:
  // Creates the cgroup directory and returns a directory FD
  // This FD is what you'll pass to clone_args.cgroup
  [[nodiscard]] static Odin::Result<void> killProcs(const CGroup& cgroup);

  // Resource Limits (Stateless & Static)
  [[nodiscard]] static Odin::Result<void> setMemoryLimit(const CGroup& cgroup, size_t max_bytes);
  [[nodiscard]] static Odin::Result<void> setProcLimit(const CGroup& cgroup, int max_pids);
  [[nodiscard]] static Odin::Result<void> setCpuLimit(const CGroup&    cgroup,
                                                      std::string_view weight);

  // Required for clone3: must enable controllers in the parent
  // before the child cgroup can enforce them.
  [[nodiscard]] static Odin::Result<void> enableSubtreeControllers(const CGroup& parent_cgroup);

private:
  static constexpr std::string_view ctx = "CGService";
  [[nodiscard]] static Odin::Result<void>
  writeCG(const CGroup& cgroup, const std::string& file_name, std::string_view value);
};

} // namespace OdinSight::System
