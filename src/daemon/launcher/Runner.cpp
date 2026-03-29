#include "Runner.hpp"
#include "CGroupService.hpp"
#include "EPollManager.hpp"
#include "GameWhitelist.hpp"
#include "IdentityService.hpp"
#include "utils/StringUtil.hpp"

// System headers
#include <cstdint>
#include <cstring> // For strerror
#include <fcntl.h>
#include <filesystem>
#include <grp.h>
#include <iostream>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace OdinSight::Daemon::Launcher {

namespace sys      = OdinSight::System;
namespace CInterop = OdinSight::Util::CInterop;
namespace fs       = std::filesystem;
using EPollBinding = OdinSight::System::EPollBinding;

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

  fs::path absWorkPath = sys::IdentityService::expandUserPath(entry->dataDir.string(), uid);
  fs::path absBinPath  = sys::IdentityService::expandUserPath(entry->binary.string(), uid);

  if (!absWorkPath.has_filename()) {
    absWorkPath = absWorkPath.parent_path();
  }

  sys::FD work_parent_fd(absWorkPath.parent_path().string(), O_PATH | O_DIRECTORY);
  sys::FD work_fd(work_parent_fd, absWorkPath.filename().string(), O_PATH | O_DIRECTORY);

  // Open File Descriptors with O_CLOEXEC to prevent leaking to other forks
  sys::FD bin_dir_fd(absBinPath.parent_path().string(), O_PATH | O_DIRECTORY);
  sys::FD exec_fd(bin_dir_fd, absBinPath.filename().string(), O_RDONLY);

  if (!exec_fd || !work_fd) {
    std::cerr << "Launcher Error: Failed to acquire directory/binary handles." << std::endl;
    return false;
  }

  sys::FD final_exec_fd = std::move(exec_fd);
  // 1. Create the anonymous memfd
  sys::FD mfd(::memfd_create(SEALED_MEMFD_NAME, MFD_CLOEXEC | MFD_ALLOW_SEALING));
  if (!mfd.isValid()) {
    std::perror("[OdinSight] memfd_create failed");
    return false;
  }

  // 2. Get the size from the disk binary
  struct stat file_info;
  if (::fstat(final_exec_fd.get(), &file_info) < 0) {
    std::perror("[OdinSight] fstat failed");
    return false;
  }

  // We move data from disk_fd to our new mfd in RAM
  if (::sendfile(mfd.get(), final_exec_fd.get(), nullptr, file_info.st_size) != file_info.st_size) {
    std::perror("[OdinSight] sendfile failed or partial copy");
    return false;
  }

  // Tell the kernel we no longer need the disk version in the Page Cache
  // 0, 0 means "the whole file"
  if (int err = ::posix_fadvise(final_exec_fd.get(), 0, 0, POSIX_FADV_DONTNEED); err != 0) {
    std::cerr << "[WARN] Failed to hint kernel to clear disk cache: " << std::strerror(err)
              << std::endl;
    // We don't return false here because the game can still run!
  }

  if (::fcntl(mfd.get(), F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL) <
      0) {
    return false;
  }

  // Comment out to disable memfd usage easier to inspect cheat without it
  final_exec_fd = std::move(mfd);

  // Create the CGroup
  auto        cgroup_name = cgroup_parent.getName() + "/game";
  sys::CGroup cgroup      = sys::CGService::create(cgroup_name);

  this->m_ctx.emplace(Context{.cg             = std::move(cgroup),
                              .executable_fd  = std::move(final_exec_fd),
                              .working_dir_fd = std::move(work_fd),
                              .uid            = uid,
                              .gid            = sys::IdentityService::getGID(uid),
                              .game_name      = entry->binary.filename().string(),
                              .envp           = sys::IdentityService::getUserEnvironment(uid),
                              .argv           = {absBinPath.string()}});

  return true;
}

void Runner::launch(const Context &ctx, EPollManager &manager) {
  if (!this->canLaunch()) {
    std::cerr << "[INFO] setup() called while previous child is active; "
                 "stopping old child.\n";
    return;
  }

  uint64_t          pid_fd_out = 0;
  struct clone_args cl_args    = {};
  cl_args.exit_signal          = SIGCHLD;
  cl_args.flags                = CLONE_INTO_CGROUP | CLONE_PIDFD;
  cl_args.pidfd                = reinterpret_cast<uintptr_t>(&pid_fd_out);
  cl_args.cgroup               = static_cast<uint64_t>(ctx.cg.get_fd());

  uid_t uid = ctx.uid;
  gid_t gid = ctx.gid;

  // Prepare argv: [game_name, bin_path, ...args]
  const std::vector<char *> argv = CInterop::toCStringVector(ctx.argv);
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

  if (pid_fd_out > 0) {
    this->m_fd.reset(static_cast<int>(pid_fd_out));

    // Create the binding so stop() is called automatically on exit
    if (!this->createEPollBinding(manager)) {
      std::cerr << "[ERROR] Failed to bind process exit event to EPoll." << std::endl;
    }
  }
}

bool Runner::createEPollBinding(EPollManager &manager) {
  // Safety check: don't create if no ring buffer, no initilization and already
  // have a binding
  if (m_binding != nullptr) {
    return false;
  }

  if (!m_fd.isValid()) {
    return false; // Libbpf couldn't provide a pollable file descriptor
  }

  auto on_event = [](void *ctx, uint32_t events) {
    auto *self = static_cast<Runner *>(ctx);
    if (self != nullptr) {
      self->stop();
    }
    // We only care about data being ready (EPOLLIN)
    // or the buffer being closed (ERR/HUP)
  };

  m_binding = std::make_unique<EPollBinding>(&manager, m_fd.get(), this, on_event);

  if (!m_binding->subscribe(EPOLLIN)) {

    m_binding.reset();
    return false;
  }

  return true;
}

void Runner::start(sys::EPollManager &manager) {
  if (this->m_ctx.has_value()) {
    this->launch(*this->m_ctx, manager);
  }
}

void Runner::stop() {
  // 1. Kill everything in the CGroup first
  m_binding.reset();

  if (this->m_ctx.has_value() && this->m_ctx->cg) {
    bool res = sys::CGService::killProcs(this->m_ctx->cg);
    if (!res) {
      std::cout << "Process termination on cgroup failed" << std::endl;
    }
  }

  // 2. Clean up the leader process tracking
  if (m_fd.isValid()) {
    siginfo_t info{};
    // Even though cgroup.kill was sent, we still need to reap the
    // zombie of the process we personally forked.
    if (::waitid(P_PIDFD, m_fd.get(), &info, WEXITED) == 0) {
      if (info.si_pid != 0) {
        std::clog << "[OdinSight] Game exited with status: " << info.si_status << std::endl;
      }
    }
  }

  this->m_gpid = -1;
  this->m_fd.reset();
  this->m_ctx.reset(); // Assuming this destroys/cleans up the CGroup
  std::cout << "stopped game and cleaned resources" << std::endl;
}

bool Runner::canLaunch() {
  // If the FD isn't valid, no process is being tracked.
  if (!m_fd.isValid()) {
    return true;
  }

  siginfo_t info{};
  // WNOWAIT is key here: it checks if the process is dead WITHOUT reaping it.
  // This allows the actual stop() function to do the formal reaping later.
  int       res = ::waitid(P_PIDFD, m_fd.get(), &info, WEXITED | WNOHANG | WNOWAIT);

  if (res == 0 && info.si_pid != 0) {
    // The process has exited (or was killed).
    // Trigger stop() to clean up CGroups and FDs.
    this->stop();
    return true;
  }

  return false;
}

const Context *Runner::getSessionInfo() const { return this->m_ctx ? &(*this->m_ctx) : nullptr; }

} // namespace OdinSight::Daemon::Launcher
