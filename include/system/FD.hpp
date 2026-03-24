#pragma once

#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace ACName::System {

class FD {
private:
  int m_fd = -1;

  bool open(const char *path, int flags, mode_t mode = 0) {
    reset();
    m_fd = ::open(path, flags | O_CLOEXEC, mode);
    return isValid();
  }

public:
  FD() noexcept = default;

  explicit FD(int file_descriptor) { this->reset(file_descriptor); }

  // Direct initialization from path
  explicit FD(const std::string &path, int flags, mode_t mode = 0) {
    bool result = open(path.c_str(), flags, mode);
    if (!result) {
      std::cout << "[ERROR] Failed to open file descriptor in FD object"
                << std::endl;
    }
  }

  // Wrap an existing raw descriptor

  // Move logic using std::exchange for conciseness
  FD(FD &&other) noexcept : m_fd(std::exchange(other.m_fd, -1)) {}

  FD &operator=(FD &&other) noexcept {
    if (this != &other) {
      reset();
      m_fd = std::exchange(other.m_fd, -1);
    }
    return *this;
  }

  // Disable copies
  FD(const FD &) = delete;
  FD &operator=(const FD &) = delete;

  ~FD() { reset(); }

  void reset(int new_fd = -1) {
    if (m_fd == new_fd) {
      return; // Prevent self assignment
    }
    if (m_fd >= 0) {
      ::close(m_fd); // Close the old one so we don't leak
    }

    if (new_fd >= 0 && ::fcntl(new_fd, F_GETFD) != -1) {

      m_fd = new_fd; // Take ownership of the new one
      return;
    }
    m_fd = -1;
  }

  [[nodiscard]] int release() { return std::exchange(m_fd, -1); }

  // Accessors
  [[nodiscard]] uint64_t getID() const {
    struct stat targetStat;
    // Ensure the FD is valid and fstat succeeds
    if (!this->isValid() || ::fstat(this->m_fd, &targetStat) == -1) {
      return 0;
    }
    // Inodes (st_ino) are the standard "ID" for files/directories in Linux
    return static_cast<uint64_t>(targetStat.st_ino);
  }

  [[nodiscard]] bool isValid() const { return m_fd >= 0; }
  [[nodiscard]] int get() const { return m_fd; }

  // Operators
  operator int() const { return m_fd; }
  explicit operator bool() const { return isValid(); }
};
} // namespace ACName::System
