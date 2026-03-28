#pragma once

#include "Context.hpp"
#include "EPollBinding.hpp"
#include "EPollManager.hpp"
#include "common/GameID.hpp"
#include "system/CGroup.hpp"
#include "system/FD.hpp"

#include <linux/sched.h>
#include <optional>
#include <sys/syscall.h>
#include <sys/types.h>

namespace OdinSight::Daemon::Launcher {

class Runner {
public:
  /** --- Public Types & Enums --- **/
  enum class LauncherStatus : int {
    Success           = 0,
    SetGroupsFailed   = 100,
    SetGidFailed      = 101,
    SetUidFailed      = 102,
    ChdirFailed       = 103,
    NoNewPrivsFailed  = 104,
    SetDumpableFailed = 105,
    ExecveFailed      = 106
  };

private:
  /** --- Private Type Aliases --- **/
  using GameID       = OdinSight::Common::GameID;
  using CGroup       = OdinSight::System::CGroup;
  using EPollManager = OdinSight::System::EPollManager;

  static constexpr const char *SEALED_MEMFD_NAME = "os_sealed_game";

  /** --- Members (State) --- **/
  std::optional<Context>                m_ctx;
  pid_t                                 m_gpid = -1;
  std::unique_ptr<System::EPollBinding> m_binding;
  System::FD                            m_fd;

public:
  /** --- Lifecycle --- **/
  Runner() = default;
  ~Runner() { stop(); }

  // Rule of Five (All deleted to ensure singleton-like process ownership)
  Runner(const Runner &)            = delete;
  Runner &operator=(const Runner &) = delete;
  Runner(Runner &&)                 = delete;
  Runner &operator=(Runner &&)      = delete;

  /** --- Setup & Control --- **/
  [[nodiscard]] bool setup(const GameID &game_id, const CGroup &cgroup_parent);
  [[nodiscard]] bool createEPollBinding(EPollManager &manager);

  void start(EPollManager &manager);
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
  void launch(const Context &ctx, EPollManager &manager);
};

} // namespace OdinSight::Daemon::Launcher
