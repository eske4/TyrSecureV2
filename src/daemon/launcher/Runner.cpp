#include "Runner.hpp"
#include "CGroupService.hpp"
#include "GameWhitelist.hpp"
#include "IdentityService.hpp"
#include "utils/StringUtil.hpp"

// System headers
#include <cstdint>
#include <cstring> // For strerror
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace OdinSight::Daemon::Launcher {

namespace sys      = OdinSight::System;
namespace CInterop = OdinSight::Util::CInterop;

bool Runner::setup(const GameID &game_id, const CGroup &cgroup_parent) {
  if (!this->canLaunch()) {
    std::cout << "Game is already running, cannot setup new context.";
    return false;
  }

  this->m_ctx.reset();
  m_gpid = -1;

  std::optional<GameEntry> entry = findGame(game_id);

  if (!entry.has_value()) {
    return false;
  }

  uid_t uid = sys::IdentityService::getUID();

  // Open File Descriptors with O_CLOEXEC to prevent leaking to other forks
  sys::FD exec_fd(entry->binary, O_PATH);
  sys::FD work_fd(entry->dataDir, O_PATH);

  // Create the CGroup
  auto        cgroup_name = cgroup_parent.getName() + "/game";
  sys::CGroup cgroup      = sys::CGService::create(cgroup_name);

  if (!exec_fd || !work_fd) {
    std::cerr << "Launcher Error: Failed to acquire directory/binary handles." << std::endl;
    return false;
  }

  this->m_ctx.emplace(Context{.cg             = std::move(cgroup),
                              .executable_fd  = std::move(exec_fd),
                              .working_dir_fd = std::move(work_fd),
                              .uid            = uid,
                              .gid            = sys::IdentityService::getGID(uid),
                              .game_name      = entry->binary.filename().string(),
                              .envp           = sys::IdentityService::getUserEnvironment(uid),
                              .argv           = {entry->binary.string()}});

  return true;
}

void Runner::launch(const Context &ctx) {
  if (!this->canLaunch()) {
    std::cerr << "[INFO] setup() called while previous child is active; "
                 "stopping old child.\n";
    return;
  }

  struct clone_args cl_args = {};
  cl_args.exit_signal       = SIGCHLD;
  cl_args.flags             = CLONE_INTO_CGROUP;
  cl_args.cgroup            = static_cast<uint64_t>(ctx.cg.get_fd());

  uid_t uid = ctx.uid;
  gid_t gid = ctx.gid;

  // Prepare argv: [game_name, bin_path, ...args]
  std::vector<std::string> final_args = ctx.argv;
  final_args.insert(final_args.begin(), ctx.game_name);

  const std::vector<char *> argv = CInterop::toCStringVector(final_args);
  const std::vector<char *> envp = CInterop::toCStringVector(ctx.envp);

  long result = ::syscall(SYS_clone3, &cl_args, sizeof(cl_args));

  if (result == -1) {
    std::cerr << "Kernel rejected clone3! " << std::strerror(errno) << " (Code: " << errno << ")"
              << std::endl;
    return;
  }

  if (result == 0) {
    // We are in the CHILD
    ::prctl(PR_SET_PDEATHSIG, SIGKILL);

    // Security Lockdown
    auto exit_err = [](LauncherStatus code) { ::_exit(static_cast<int>(code)); };

    if (::setgroups(0, nullptr) < 0) {
      exit_err(LauncherStatus::SetGroupsFailed);
    }

    if (::setresgid(gid, gid, gid) < 0) {
      exit_err(LauncherStatus::SetGidFailed);
    }

    if (::setresuid(uid, uid, uid) < 0) {
      exit_err(LauncherStatus::SetUidFailed);
    }

    if (::fchdir(ctx.working_dir_fd.get()) < 0) {
      exit_err(LauncherStatus::ChdirFailed);
    }

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
      exit_err(LauncherStatus::NoNewPrivsFailed);
    }

    if (::prctl(PR_SET_DUMPABLE, 0) < 0) {
      exit_err(LauncherStatus::SetDumpableFailed);
    }

    ::fexecve(ctx.executable_fd.get(), argv.data(), envp.data());

    // If we reach here, exec failed
    exit_err(LauncherStatus::ExecveFailed);
  }

  this->m_gpid = static_cast<pid_t>(result);
}

void Runner::start() {
  if (this->m_ctx.has_value()) {
    this->launch(*this->m_ctx);
  }
}

void Runner::stop() {
  // 1. Kill everything in the CGroup first
  if (this->m_ctx.has_value() && this->m_ctx->cg) {
    bool res = sys::CGService::killProcs(this->m_ctx->cg);
    if (!res) {
      std::cout << "Process termination on cgroup failed" << std::endl;
    }
  }

  // 2. Clean up the leader process tracking
  if (this->m_gpid > 0) {
    int status;
    // Even though cgroup.kill was sent, we still need to reap the
    // zombie of the process we personally forked.
    ::waitpid(this->m_gpid, &status, WNOHANG);
  }

  this->m_gpid = -1;
  this->m_ctx.reset(); // Assuming this destroys/cleans up the CGroup
  std::cout << "stopped game" << std::endl;
}

bool Runner::canLaunch() {
  if (m_gpid <= 0) {
    return true;
  }

  int   status;
  // Non-blocking check to see if the process has changed state
  pid_t result = ::waitpid(m_gpid, &status, WNOHANG);

  if (result == m_gpid || (result == -1 && errno == ECHILD)) {
    // The process is dead/reaped.
    // IMPORTANT: Trigger stop() here to wipe the rest of the CGroup!
    this->stop();
    return true;
  }

  // Fallback: Check if it's still alive but not a child (shouldn't happen here)
  if (::kill(m_gpid, 0) == -1 && errno == ESRCH) {
    this->stop();
    return true;
  }

  return false;
}

const Context *Runner::getSessionInfo() const { return this->m_ctx ? &(*this->m_ctx) : nullptr; }

} // namespace OdinSight::Daemon::Launcher
