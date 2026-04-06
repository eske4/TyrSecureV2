#pragma once

#include "common/Result.hpp"
#include "system/FD.hpp"
#include <filesystem>
#include <sys/types.h>

namespace OdinSight::System {

class FDService final {
public:
  [[nodiscard]] static Odin::Result<FD> openFile(std::filesystem::path path,
                                                 bool                  is_readable = false);
  [[nodiscard]] static Odin::Result<FD> openBin(std::filesystem::path path);
  [[nodiscard]] static Odin::Result<FD> openDir(std::filesystem::path path);
};

} // namespace OdinSight::System
