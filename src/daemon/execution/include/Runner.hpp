#pragma once

#include "Context.hpp"
#include "GameWhitelist.hpp"
#include "common/GameID.hpp"
#include "common/Result.hpp"
#include "system/CGroup.hpp"
#include "system/FD.hpp"

#include <linux/sched.h>
#include <optional>
#include <sys/syscall.h>
#include <sys/types.h>

namespace OdinSight::Daemon::Launcher {

class Runner final {
  static constexpr uint64_t GIB_TO_BYTES    = 1024ULL * 1024 * 1024;
  static constexpr uint64_t MAX_GAME_MEMORY = 4ULL * GIB_TO_BYTES;
  static constexpr int      MAX_GAME_PROCS  = 1024;

private:
  /** --- Private Type Aliases --- **/
  using GameID    = OdinSight::Common::GameID;
  using CGroup    = OdinSight::System::CGroup;
  using FD        = OdinSight::System::FD;
  using GameEntry = OdinSight::Daemon::Launcher::GameEntry;

  static constexpr const char*      SEALED_MEMFD_NAME = "os_sealed_game";
  static constexpr std::string_view lctx              = "Launcher::Runner";

  /** --- Members (State) --- **/
  std::optional<Context>  m_ctx  = std::nullopt;
  pid_t                   m_gpid = -1;
  FD                      m_fd   = FD::empty();
  std::shared_ptr<CGroup> m_cg;

  Runner() = default;

public:
  /** --- Lifecycle --- **/
  ~Runner() { stop(); }

  // Rule of Five (All deleted to ensure singleton-like process ownership)
  Runner(const Runner&)            = delete;
  Runner& operator=(const Runner&) = delete;
  Runner(Runner&&)                 = delete;
  Runner& operator=(Runner&&)      = delete;

  static Odin::Result<std::unique_ptr<Runner>> create(std::shared_ptr<CGroup> parent_cg);

  /** --- Setup & Control --- **/
  [[nodiscard]] Odin::Result<void> setup(const GameID& game_id);
  [[nodiscard]] Odin::Result<void> start();

  /** --- Cleaning --- **/
  void clearRuntimeState();
  void stop();

  /** --- Status Queries --- **/
  [[nodiscard]] bool      isActive() const { return m_ctx.has_value() && m_gpid != -1; }
  [[nodiscard]] bool      isPrepared() const { return m_ctx.has_value() && m_gpid == -1; }
  [[nodiscard]] bool      canLaunch();
  [[nodiscard]] pid_t     getGpid() const { return m_gpid; }
  [[nodiscard]] const FD& getFd() const { return m_fd; }
  [[nodiscard]] std::shared_ptr<CGroup> getCGroup() const noexcept { return m_cg; }

  [[nodiscard]] const Context* getSessionInfo() const;

private:
  /** --- Internal Helpers --- **/
  /**
   * @brief The internal syscall logic (clone3/fexecve).
   * @param ctx The local context prepared by start().
   */
  void launch(const Context& ctx);
  // Helper functions for setup
  [[nodiscard]] static Odin::Result<std::tuple<FD, FD, std::string>>
                                        resolve_paths(const GameEntry& entry, uid_t uid);
  [[nodiscard]] static Odin::Result<FD> create_sealed_memfd(const FD& disk_exec_fd);

  // Helper Function for start
  void execute_child_setup(int error_fd, const std::vector<char*>& argv,
                           const std::vector<char*>& envp);
};

} // namespace OdinSight::Daemon::Launcher
