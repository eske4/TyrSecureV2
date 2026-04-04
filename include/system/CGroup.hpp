#pragma once

#include "FD.hpp"
#include "common/Result.hpp"
#include <cstdint>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace OdinSight::System {

class CGroup final {
  static constexpr int              MAX_RETRY_ATTEMPTS = 10;
  static constexpr int              MAX_SLEEP_TIME     = 100;
  static constexpr std::string_view ctx                = "System::CGroup";

  using Error = Odin::Error;

private:
  std::string             m_name;
  std::filesystem::path   m_path;
  std::shared_ptr<CGroup> m_parent = nullptr;
  FD                      m_fd;
  uint64_t                m_id = 0;

  // Private constructor for factories
  CGroup(std::string name, std::filesystem::path path, FD file_descriptor, uint64_t cg_id,
         std::shared_ptr<CGroup> parent = nullptr)
      : m_name(std::move(name)), m_path(std::move(path)), m_fd(std::move(file_descriptor)),
        m_id(cg_id), m_parent(parent) {}

  inline void cleanup() noexcept;

public:
  CGroup()                         = delete;
  CGroup(const CGroup&)            = delete;
  CGroup& operator=(const CGroup&) = delete;

  // Move Constructor
  CGroup(CGroup&& other) noexcept
      : m_name(std::move(other.m_name)), m_path(std::move(other.m_path)),
        m_fd(std::move(other.m_fd)), m_id(std::exchange(other.m_id, 0)),
        m_parent(std::move(other.m_parent)) {}

  // Move Assignment
  CGroup& operator=(CGroup&& other) noexcept {
    if (this != &other) {
      cleanup();
      m_name   = std::move(other.m_name);
      m_path   = std::move(other.m_path);
      m_parent = std::move(other.m_parent);
      m_fd     = std::move(other.m_fd);
      m_id     = std::exchange(other.m_id, 0);
    }
    return *this;
  }

  ~CGroup() { cleanup(); }

  // --- Factories ---
  [[nodiscard]] static Odin::Result<std::shared_ptr<CGroup>> create(std::string_view name) noexcept;
  [[nodiscard]] static Odin::Result<std::shared_ptr<CGroup>>
  createAt(std::shared_ptr<CGroup> parent_cg,

           std::string name) noexcept;
  [[nodiscard]] static Odin::Result<std::shared_ptr<CGroup>> empty() noexcept;

  void close() { cleanup(); }

  // --- Accessors ---
  [[nodiscard]] explicit           operator bool() const noexcept { return m_fd && m_id > 0; }
  [[nodiscard]] const FD&          getFD() const noexcept { return m_fd; }
  [[nodiscard]] const std::string& getName() const noexcept { return m_name; }
  [[nodiscard]] const std::filesystem::path& getPath() const noexcept { return m_path; }
  [[nodiscard]] uint64_t                     getID() const noexcept { return m_id; }
  [[nodiscard]] std::shared_ptr<CGroup>      getParent() const noexcept { return m_parent; }
};

// =================================================================
// Implementatio
// =================================================================

inline void CGroup::cleanup() noexcept {
  if (m_name.empty() || !m_fd.isValid()) { return; }

  // 1. Send the Kill Signal
  if (auto kill_res = FD::openAt(m_fd, "cgroup.kill", O_WRONLY)) {
    FD kfd = std::move(*kill_res);
    (void) ::write(kfd.get(), "1", 1);
  }

  // 2. Release handle so rmdir isn't busy
  m_fd.close();

  // 3. The Guarantee Loop
  std::error_code err;
  for (int attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
    if (std::filesystem::remove(m_path, err) || err == std::errc::no_such_file_or_directory) {
      return;
    }

    if (err == std::errc::device_or_resource_busy) {
      int sleep_ms = std::min(MAX_SLEEP_TIME, (1 << attempt) * 10);
      std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
      continue;
    }
    break;
  }

  if (err) {
    std::clog << "[Cleanup] FATAL: Could not remove " << m_path << " - " << err.message() << "\n";
  }
}

inline Odin::Result<std::shared_ptr<CGroup>> CGroup::create(std::string_view name) noexcept {
  if (name.empty()) { return std::unexpected(Error::Logic(ctx, "create", "Name cannot be empty")); }

  std::filesystem::path target_path = std::filesystem::path("/sys/fs/cgroup") / name;
  std::error_code       err_code;

  if (!std::filesystem::create_directories(target_path, err_code) && err_code) {
    return std::unexpected(Error::System(ctx, "mkdir", err_code.value()));
  }

  auto fd_res = FD::open(target_path.string(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (!fd_res) { return std::unexpected(Error::Enrich(ctx, "open_dir", fd_res.error())); }

  auto id_res = fd_res->getID();
  if (!id_res) { return std::unexpected(Error::Enrich(ctx, "get_id", id_res.error())); }

  auto* ptr = new (std::nothrow)
      CGroup(std::string(name), std::move(target_path), std::move(*fd_res), *id_res, nullptr);

  if (ptr == nullptr) {
    return std::unexpected(Error::Logic(ctx, "create", "Memory allocation failed"));
  }

  return std::shared_ptr<CGroup>(ptr);
  ;
}

inline Odin::Result<std::shared_ptr<CGroup>> CGroup::createAt(std::shared_ptr<CGroup> parent_cg,
                                                              std::string name) noexcept {
  if (!parent_cg || name.empty()) {
    return std::unexpected(Error::Logic(ctx, "createAt", "Invalid arguments"));
  }

  const FD& p_fd = parent_cg->getFD();

  if (::mkdirat(p_fd.get(), name.c_str(), 0755) < 0 && errno != EEXIST) {
    return std::unexpected(Error::System(ctx, "mkdirat", errno));
  }

  auto child_fd_res = FD::openAt(p_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (!child_fd_res) {
    return std::unexpected(Error::Enrich(ctx, "open_child_dir", child_fd_res.error()));
  }

  auto id_res = child_fd_res->getID();
  if (!id_res) { return std::unexpected(Error::Enrich(ctx, "get_child_id", id_res.error())); }

  std::filesystem::path full_path = parent_cg->getPath() / name;

  // 4. Safe Allocation: Use std::nothrow to prevent exceptions in a noexcept function
  auto* ptr = new (std::nothrow)
      CGroup(std::move(name), std::move(full_path), std::move(*child_fd_res), *id_res,
             parent_cg // This fills the m_parent slot and increments the ref count
      );

  if (ptr == nullptr) {
    return std::unexpected(Error::Logic(ctx, "createAt", "Memory allocation failed"));
  }

  return std::shared_ptr<CGroup>(ptr);
}

inline Odin::Result<std::shared_ptr<CGroup>> CGroup::empty() noexcept {
  auto* ptr = new (std::nothrow) CGroup("", {}, FD::empty(), 0, nullptr);

  if (ptr == nullptr) { std::unexpected(Error::Logic(ctx, "empty", "Memory allocation failed")); }

  return std::shared_ptr<CGroup>(ptr);
}

} // namespace OdinSight::System
