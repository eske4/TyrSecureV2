#include "FDService.hpp"

namespace OdinSight::System {

[[nodiscard]] Odin::Result<FD> FDService::openFile(std::filesystem::path path) {
  using FD     = OdinSight::System::FD;
  auto dir_val = FD::open(path.parent_path().string(), O_PATH | O_DIRECTORY | O_CLOEXEC);

  if (!dir_val) { return std::unexpected(dir_val.error()); }

  auto final_fd = FD::openAt(*dir_val, path.filename().string(), O_PATH | O_NOFOLLOW | O_CLOEXEC);

  if (!final_fd) { return std::unexpected(final_fd.error()); }

  return final_fd; // Return the Result containing the FD
}
} // namespace OdinSight::System
