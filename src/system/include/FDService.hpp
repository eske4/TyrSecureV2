#pragma once

#include "common/Result.hpp"
#include "system/FD.hpp"
#include <filesystem>
#include <sys/types.h>

namespace OdinSight::System {

class FDService final {
public:
  [[nodiscard]] static Odin::Result<FD> openFile(std::filesystem::path path);
};

} // namespace OdinSight::System
