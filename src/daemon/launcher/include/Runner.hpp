#pragma once

#include "Context.hpp"
#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include "GameWhitelist.hpp"
#include "common/GameID.hpp"
#include "system/CGroup.hpp"
#include "system/FD.hpp"

#include <linux/sched.h>
#include <optional>
#include <sys/syscall.h>
#include <sys/types.h>

namespace OdinSight::Daemon::Launcher {

class Runner final {
private:
  /** --- Private Type Aliases --- **/
  using GameID       = OdinSight::Common::GameID;
  using CGroup       = OdinSight::System::CGroup;
  using EPollManager = OdinSight::System::EPollManager;
  using FD           = OdinSight::System::FD;
  using GameEntry    = OdinSight::Daemon::Launcher::GameEntry;

  template <typename T> using Result = std::expected<T, std::error_code>;

  static constexpr const char *SEALED_MEMFD_NAME = "os_sealed_game";

  /** --- Members (State) --- **/
  std::optional<Context> m_ctx  = std::nullopt;
  pid_t                  m_gpid = -1;
  FD                     m_fd   = FD::empty();

  Runner() = default;

public:
  /** --- Lifecycle --- **/
  ~Runner() { stop(); }

  // Rule of Five (All deleted to ensure singleton-like process ownership)
  Runner(const Runner &)            = delete;
  Runner &operator=(const Runner &) = delete;
  Runner(Runner &&)                 = delete;
  Runner &operator=(Runner &&)      = delete;

  static Result<std::unique_ptr<Runner>> create();

  /** --- Setup & Control --- **/
  [[nodiscard]] Result<void> setup(const GameID &game_id, std::shared_ptr<CGroup> &cgroup_parent);
  Result<void>               start(EPollManager &manager);

  /** --- Cleaning --- **/
  void clearRuntimeState();
  void stop();

  /** --- Status Queries --- **/
  [[nodiscard]] bool           isActive() const { return m_ctx.has_value() && m_gpid != -1; }
  [[nodiscard]] bool           isPrepared() const { return m_ctx.has_value() && m_gpid == -1; }
  [[nodiscard]] bool           canLaunch();
  [[nodiscard]] pid_t          getGpid() const { return m_gpid; }
  [[nodiscard]] const Context *getSessionInfo() const;

private:
  /** --- Internal Helpers --- **/
  /**
   * @brief The internal syscall logic (clone3/fexecve).
   * @param ctx The local context prepared by start().
   */
  void                                           launch(const Context &ctx, EPollManager &manager);
  // Helper functions for setup
  static Result<std::tuple<FD, FD, std::string>> resolve_paths(const GameEntry &entry, uid_t uid);
  [[nodiscard]] static Result<FD>                create_sealed_memfd(const FD &disk_exec_fd);

  // Helper Function for start
  void execute_child_setup(int error_fd, const std::vector<char *> &argv,
                           const std::vector<char *> &envp);
};

} // namespace OdinSight::Daemon::Launcher
