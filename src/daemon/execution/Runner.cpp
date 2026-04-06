#include "Runner.hpp"
#include "CGroupService.hpp"
#include "GameWhitelist.hpp"
#include "IdentityService.hpp"
#include "common/Result.hpp"
#include "system/FD.hpp"
#include "utils/StringUtil.hpp"

#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <grp.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <optional>
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
namespace Util     = OdinSight::Util;

using FD              = OdinSight::System::FD;
using IdentityService = OdinSight::System::IdentityService;
using CGService       = OdinSight::System::CGService;

using Error = Odin::Error;

Odin::Result<std::unique_ptr<Runner>> Runner::create(std::shared_ptr<CGroup> parent_cg) {
  auto instance = std::unique_ptr<Runner>(new Runner());

  if (!instance) {
    return std::unexpected(Odin::Error::Logic(lctx, "create", "Memory allocation failed"));
  }

  auto cgroup_res = CGroup::createAt(parent_cg, "game");
  if (!cgroup_res) {
    return std::unexpected(Error::Enrich(lctx, "create_cgroup", cgroup_res.error()));
  }

  auto& game_cg = cgroup_res.value();
  auto  mem_res = CGService::setMemoryLimit(*game_cg, MAX_GAME_MEMORY);
  if (!mem_res) {
    return std::unexpected(Error::Enrich(lctx, "set_memory_limit", mem_res.error()));
  }

  // 2. Set Process Limit (1024)
  auto proc_res = CGService::setProcLimit(*game_cg, MAX_GAME_PROCS);
  if (!proc_res) {
    return std::unexpected(Error::Enrich(lctx, "set_proc_limit", proc_res.error()));
  }

  instance->m_ctx  = std::nullopt;
  instance->m_fd   = FD::empty();
  instance->m_gpid = -1;
  instance->m_cg   = game_cg;

  return instance;
}

Odin::Result<void> Runner::setup(const GameID& game_id) {
  // 1. Validation & State Reset
  if (!this->canLaunch()) {
    return std::unexpected(
        Error::Logic(lctx, "setup", "Runner is already active or in a bad state"));
  }
  stop();
  m_gpid = -1;

  // 2. Resolve Game & Identity (The "Who" and "What")
  auto entry = findGame(game_id);
  if (!entry) {
    return std::unexpected(Error::Logic(lctx, "setup", "Game not found in whitelist"));
  }

  auto uid_res = IdentityService::getUID();
  if (!uid_res) { return std::unexpected(Error::Enrich(lctx, "resolve_uid", uid_res.error())); }

  auto gid_res = IdentityService::getGID(*uid_res);
  if (!gid_res) { return std::unexpected(Error::Enrich(lctx, "resolve_gid", gid_res.error())); }

  auto env_res = IdentityService::getUserEnvironment(*uid_res);
  if (!env_res) { return std::unexpected(Error::Enrich(lctx, "resolve_env", env_res.error())); }

  auto paths_res = resolve_paths(*entry, *uid_res);
  if (!paths_res) {
    return std::unexpected(Error::Enrich(lctx, "resolve_paths", paths_res.error()));
  }

  auto [work_fd, disk_exec_fd, absBinPath] = std::move(*paths_res);

  FD final_exec_fd = std::move(disk_exec_fd);
  {
    // --------------------------------------------------- //
    // Comment to disable disk to ram ghosting for testing //
    // --------------------------------------------------- //
    auto ghost_res = create_sealed_memfd(final_exec_fd);
    if (!ghost_res) { return std::unexpected(Error::Enrich(lctx, "ghosting", ghost_res.error())); }
    ::posix_fadvise(final_exec_fd.get(), 0, 0, POSIX_FADV_DONTNEED);

    final_exec_fd = std::move(*ghost_res);
  }

  this->m_ctx.emplace(Context{.executable_fd  = std::move(final_exec_fd),
                              .working_dir_fd = std::move(work_fd),
                              .uid            = *uid_res,
                              .gid            = *gid_res,
                              .game_name      = entry->binary.filename().string(),
                              .envp           = std::move(*env_res),
                              .argv           = {std::move(absBinPath)}});

  return {};
}

Odin::Result<std::tuple<FD, FD, std::string>> Runner::resolve_paths(const GameEntry& entry,
                                                                    uid_t            uid) {
  // 1. Path Expansion
  auto work_path_res = sys::IdentityService::expandUserPath(entry.dataDir.string(), uid);
  auto bin_path_res  = sys::IdentityService::expandUserPath(entry.binary.string(), uid);

  if (!work_path_res) {
    return std::unexpected(Error::Enrich(lctx, "expand_work_path", work_path_res.error()));
  }
  if (!bin_path_res) {
    return std::unexpected(Error::Enrich(lctx, "expand_bin_path", bin_path_res.error()));
  }

  std::filesystem::path absWorkPath = *work_path_res;
  std::filesystem::path absBinPath  = *bin_path_res;

  if (!absWorkPath.has_filename() && absWorkPath.has_parent_path()) {
    absWorkPath = absWorkPath.parent_path();
  }

  // 2. Resolve Working Directory
  auto work_parent_res = FD::open(absWorkPath.parent_path().string(), O_PATH | O_DIRECTORY);
  if (!work_parent_res) {
    return std::unexpected(Error::Enrich(lctx, "open_work_parent", work_parent_res.error()));
  }

  // Pass the Result's value (the FD object) directly to openAt
  auto work_fd_res = FD::openAt(*work_parent_res, absWorkPath.filename().string(),
                                O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (!work_fd_res) {
    return std::unexpected(Error::Enrich(lctx, "open_work_dir", work_fd_res.error()));
  }

  // 3. Resolve Binary
  auto bin_dir_res = FD::open(absBinPath.parent_path().string(), O_PATH | O_DIRECTORY);
  if (!bin_dir_res) {
    return std::unexpected(Error::Enrich(lctx, "open_bin_parent", bin_dir_res.error()));
  }

  // Pass the Result's value (the FD object) directly to openAt
  auto exec_fd_res = FD::openAt(*bin_dir_res, absBinPath.filename().string(), O_RDONLY | O_CLOEXEC);
  if (!exec_fd_res) {
    return std::unexpected(Error::Enrich(lctx, "open_bin_file", exec_fd_res.error()));
  }

  // Return the verified pair
  return std::make_tuple(std::move(*work_fd_res), std::move(*exec_fd_res), absBinPath.string());
}

Odin::Result<FD> Runner::create_sealed_memfd(const FD& disk_exec_fd) {
  if (!disk_exec_fd) { return std::unexpected(Error::Logic(lctx, "memfd", "Invalid disk FD")); }

  auto mfd_raw = ::memfd_create("odin_ghost", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (mfd_raw < 0) { return std::unexpected(Error::System(lctx, "memfd_create", errno)); }

  auto mfd = FD::adopt(mfd_raw);
  if (!mfd) { return std::unexpected(Error::Enrich(lctx, "memfd_adopt", mfd.error())); }

  struct stat stat_res;
  if (::fstat(disk_exec_fd.get(), &stat_res) < 0) {
    return std::unexpected(Error::System(lctx, "fstat_exec", errno));
  }

  if (::sendfile(mfd->get(), disk_exec_fd.get(), nullptr, stat_res.st_size) != stat_res.st_size) {
    return std::unexpected(Error::System(lctx, "sendfile", errno));
  }

  if (::fcntl(mfd->get(), F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL) <
      0) {
    return std::unexpected(Error::System(lctx, "memfd_seal", errno));
  }

  return std::move(*mfd);
}

Odin::Result<void> Runner::start() {
  if (!m_ctx.has_value()) {
    return std::unexpected(Error::Logic(lctx, "start", "No context prepared"));
  }

  const auto& ctx = *m_ctx;

  if (!canLaunch()) {
    return std::unexpected(Error::Logic(lctx, "start", "Process already running"));
  }

  const auto& cgroup_res = m_cg->getFD();
  if (!cgroup_res) { return std::unexpected(Error::Logic(lctx, "start", "Invalid CGroup FD")); }

  // 1. Prepare Arguments & Pipe
  const std::vector<char*> argv = CInterop::toCStringVector(ctx.argv);
  const std::vector<char*> envp = CInterop::toCStringVector(ctx.envp);

  int pipe_fds[2];
  if (::pipe2(pipe_fds, O_CLOEXEC) == -1) {
    return std::unexpected(Error::System(lctx, "pipe_create", errno));
  }

  auto read_pipe  = FD::adopt(pipe_fds[0]);
  auto write_pipe = FD::adopt(pipe_fds[1]);
  if (!read_pipe || !write_pipe) {
    return std::unexpected(Error::Logic(lctx, "start", "Failed to adopt pipe FDs"));
  }

  // 2. Setup Clone Args
  uint64_t          pid_fd_out = static_cast<uint64_t>(-1);
  struct clone_args cl_args    = {
      .flags       = CLONE_INTO_CGROUP | CLONE_PIDFD,
      .pidfd       = reinterpret_cast<uintptr_t>(&pid_fd_out),
      .exit_signal = SIGCHLD,
      .cgroup      = static_cast<uint64_t>(*cgroup_res),
  };

  // 3. The Fork/Clone
  long result = ::syscall(SYS_clone3, &cl_args, sizeof(cl_args));

  if (result == -1) { return std::unexpected(Error::System(lctx, "clone3", errno)); }

  if (result == 0) {
    /** --- CHILD PROCESS PATH --- **/
    read_pipe->close();

    // execute_child_setup calls fexecve and only returns on failure.
    // Inside, it reports errors via write_pipe.
    if (write_pipe) { this->execute_child_setup(write_pipe->get(), argv, envp); }
    ::_exit(EXIT_FAILURE);
  }

  /** --- PARENT PROCESS PATH --- **/
  // CRITICAL: Close write end immediately so the read below can reach EOF on child success
  write_pipe->close();

  int     child_errno = 0;
  ssize_t bytes       = ::read(read_pipe->get(), &child_errno, sizeof(child_errno));

  if (bytes == -1) {
    int err = (errno == EINTR) ? ETIMEDOUT : errno;
    return std::unexpected(Error::System(lctx, "pipe_read", err));
  }
  if (bytes > 0) {
    // The child sent an error code before it could exec
    return std::unexpected(Error::System(lctx, "child_exec_prep", child_errno));
  }

  // Success! Process is now executing the target binary.
  m_gpid = static_cast<pid_t>(result);

  if (auto res = FD::adopt(static_cast<int>(pid_fd_out))) { m_fd = std::move(res.value()); }

  return {};
}

void Runner::execute_child_setup(int error_fd, const std::vector<char*>& argv,
                                 const std::vector<char*>& envp) {
  if (!m_ctx.has_value()) { ::_exit(EXIT_FAILURE); }

  auto report_and_exit = [&](int err) {
    [[maybe_unused]] auto unused = ::write(error_fd, &err, sizeof(err));
    ::_exit(EXIT_FAILURE);
  };

  // Linear sequence of sandbox constraints
  if (::prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) { report_and_exit(errno); }
  if (::setgroups(0, nullptr) < 0) { report_and_exit(errno); }
  if (::setresgid(m_ctx->gid, m_ctx->gid, m_ctx->gid) < 0) { report_and_exit(errno); }
  if (::setresuid(m_ctx->uid, m_ctx->uid, m_ctx->uid) < 0) { report_and_exit(errno); }

  if (::fchdir(m_ctx->working_dir_fd.get()) < 0) { report_and_exit(errno); }
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { report_and_exit(errno); }
  if (::prctl(PR_SET_DUMPABLE, 0) < 0) { report_and_exit(errno); }

  ::fexecve(m_ctx->executable_fd.get(), argv.data(), envp.data());

  // If we're here, exec failed
  report_and_exit(errno);
}

void Runner::stop() {
  m_ctx.reset();

  // 1. CGroup Cleanup
  if (m_cg) {
    if (auto res = CGService::killProcs(*m_cg); !res) { res.error().log(); }
    if (auto res = m_cg->refresh(); !res) { res.error().log(); }
  }

  // 2. Process Reaping (Clean & Readable)
  siginfo_t  info{};
  const bool has_proc = m_fd.isValid();
  const bool reaped   = has_proc && ::waitid(P_PIDFD, m_fd.get(), &info, WEXITED | WNOHANG) == 0;
  const bool exited   = reaped && info.si_pid != 0;

  if (exited) { Odin::Error::Logic("Runner", "reap", "PID exited").log(); }

  clearRuntimeState();
}

bool Runner::canLaunch() {
  // If the FD isn't valid, no process is being tracked.
  if (!m_fd) { return true; }

  siginfo_t info{};

  // WNOWAIT is key here: it checks if the process is dead WITHOUT reaping it.
  // This allows the actual stop() function to do the formal reaping later.

  int res = ::waitid(P_PIDFD, m_fd.get(), &info, WEXITED | WNOHANG | WNOWAIT);

  if (res == 0 && info.si_pid != 0) {
    clearRuntimeState();
    return true;
  }

  return false;
}

void Runner::clearRuntimeState() {
  m_gpid = -1;
  m_fd   = FD::empty();
}

const Context* Runner::getSessionInfo() const { return this->m_ctx ? &(*this->m_ctx) : nullptr; }

} // namespace OdinSight::Daemon::Launcher
