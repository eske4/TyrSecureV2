#pragma once

#include "FD.hpp"

#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <thread>
#include <unistd.h>

namespace OdinSight::System {

class CGroup {
public:
  CGroup() = default;
  CGroup(std::string name, std::filesystem::path path, FD file_descriptor, uint64_t cg_id = 0) {
    this->name = name;
    this->path = path;
    this->fd   = std::move(file_descriptor);
    this->id   = cg_id;
  }

  // 1. & 2. Disable Copying (Prevents double-kill)
  CGroup(const CGroup &)            = delete;
  CGroup &operator=(const CGroup &) = delete;

  // 3. Move Constructor (Safely transfers ownership)
  CGroup(CGroup &&other) noexcept
      : name(std::move(other.name)), path(std::move(other.path)), fd(std::move(other.fd)),
        id(other.id) {}

  // 4. Move Assignment: DELETE (Prevents the "confusing" swap behavior)
  CGroup  &operator=(CGroup &&other) noexcept = delete;
  explicit operator bool() const noexcept { return fd.isValid(); }

  // 5. Destructor
  ~CGroup() {

    if (this->fd.get() < 0 || !fd.isValid()) {

      return;
    }
    // 1. Nuclear kill
    int kill_fd = ::openat(this->fd.get(), "cgroup.kill", O_WRONLY);
    if (kill_fd >= 0) {
      ::write(kill_fd, "1", 1);
      ::close(kill_fd);
    }

    this->fd.reset();

    std::error_code err_code;

    static constexpr int MAX_RETRY_ATTEMPTS = 10;

    for (int i = 0; i < MAX_RETRY_ATTEMPTS; ++i) { // Retry for ~50ms
      if (!std::filesystem::exists(path, err_code)) {
        break;
      }
      if (std::filesystem::remove(path, err_code)) {
        break;
      }

      if (err_code.value() != static_cast<int>(std::errc::device_or_resource_busy)) {
        break;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(MAX_RETRY_ATTEMPTS << i));
    }
  }

  // Accessors
  [[nodiscard]] const FD          &get_fd() const { return this->fd; }
  [[nodiscard]] const std::string &getName() const { return name; }
  [[nodiscard]] uint64_t           getID() const { return this->id; }

private:
  std::string           name;
  std::filesystem::path path = "";
  FD                    fd;
  uint64_t              id;
};

} // namespace OdinSight::System
