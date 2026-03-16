#pragma once

#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace sys {

class FD {
private:
  int fd = -1;

public:
  FD() = default;

  // Direct initialization from path
  explicit FD(const std::string &path, int flags, mode_t mode = 0) {
    bool result = open(path.c_str(), flags, mode);
    if (!result) {
      std::cout << "[ERROR] Failed to open file descriptor in FD object"
                << std::endl;
    }
  }

  // Wrap an existing raw descriptor
  explicit FD(int file_descriptor) : fd(file_descriptor) {}

  // Move logic using std::exchange for conciseness
  FD(FD &&other) noexcept : fd(std::exchange(other.fd, -1)) {}

  FD &operator=(FD &&other) noexcept {
    if (this != &other) {
      reset();
      fd = std::exchange(other.fd, -1);
    }
    return *this;
  }

  // Disable copies
  FD(const FD &) = delete;
  FD &operator=(const FD &) = delete;

  ~FD() { reset(); }

  [[nodiscard]] bool open(const char *path, int flags, mode_t mode = 0) {
    reset();
    fd = ::open(path, flags | O_CLOEXEC, mode);
    return isValid();
  }

  void reset(int new_fd = -1) {
    if (fd == new_fd) {
      return; // Prevent self assignment
    }
    if (fd >= 0) {
      ::close(fd); // Close the old one so we don't leak
    }

    if (new_fd >= 0 && ::fcntl(new_fd, F_GETFD) != -1) {

      fd = new_fd; // Take ownership of the new one
      return;
    }
    fd = -1;
  }

  [[nodiscard]] int release() { return std::exchange(fd, -1); }

  // Accessors
  [[nodiscard]] uint64_t getID() const {
    struct stat targetStat;
    // Ensure the FD is valid and fstat succeeds
    if (!this->isValid() || ::fstat(this->fd, &targetStat) == -1) {
      return 0;
    }
    // Inodes (st_ino) are the standard "ID" for files/directories in Linux
    return static_cast<uint64_t>(targetStat.st_ino);
  }

  [[nodiscard]] bool isValid() const { return fd >= 0; }
  [[nodiscard]] int get() const { return fd; }

  // Operators
  operator int() const { return fd; }
  explicit operator bool() const { return isValid(); }
};
} // namespace sys
