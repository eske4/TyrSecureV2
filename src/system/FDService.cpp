#include "FDService.hpp"
namespace OdinSight::System {

[[nodiscard]] Odin::Result<FD> FDService::openFile(std::filesystem::path path, bool is_readable) {
  using FD     = OdinSight::System::FD;
  auto dir_val = FD::open(path.parent_path().string(), O_PATH | O_DIRECTORY | O_CLOEXEC);

  if (!dir_val) { return std::unexpected(dir_val.error()); }

  int flags = (is_readable ? O_RDONLY : O_PATH) | O_NOFOLLOW | O_CLOEXEC;

  return FD::openAt(*dir_val, path.filename().string(), flags);
}

[[nodiscard]] Odin::Result<FD> FDService::openDir(std::filesystem::path path) {
  auto dir_val = FD::open(path.parent_path().string(), O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (!dir_val) { return std::unexpected(dir_val.error()); }

  return FD::openAt(*dir_val, path.filename().string(),
                    O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

[[nodiscard]] Odin::Result<FD> FDService::openBin(std::filesystem::path path) {
  auto dir_val = FD::open(path.parent_path().string(), O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (!dir_val) { return std::unexpected(dir_val.error()); }

  // O_RDONLY is critical here so that sendfile() in the ghosting logic works
  return FD::openAt(*dir_val, path.filename().string(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
}

} // namespace OdinSight::System
