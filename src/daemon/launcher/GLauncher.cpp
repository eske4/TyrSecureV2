#include "IdentityProvider.hpp"
#include "CGService.hpp"
#include "GLauncher.hpp"
#include "common/LauncherStatus.hpp"
#include "utils/StringUtil.hpp"
#include "GameWhitelist.hpp"

// System headers
#include <cstdint>
#include <grp.h>
#include <iostream>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <cstring> // For strerror

namespace Launcher {

bool GLauncher::setup(const common::GameID &game_id,
                      const sys::CGroup& cgroup_parent) {
    
    this->stop();

    std::optional<GameEntry> entry = findGame(game_id);

    if(!entry.has_value()) {
        return false;
    }

    uid_t uid = sys::IdentityProvider::getUID();
    
    // Open File Descriptors with O_CLOEXEC to prevent leaking to other forks
    sys::FD exec_fd(entry->binary, O_PATH);
    sys::FD work_fd(entry->dataDir, O_PATH);
    
    // Create the CGroup
    auto cgroup_name = cgroup_parent.getName() + "/game";
    sys::CGroup cgroup = sys::CGService::create(cgroup_name);

    if (!exec_fd || !work_fd) {
        std::cerr << "Launcher Error: Failed to acquire directory/binary handles." << std::endl;
        return false; 
    }

    this->ctx.emplace(LContext{
        .cg = std::move(cgroup),
        .executable_fd = std::move(exec_fd),
        .working_dir_fd = std::move(work_fd),
        .uid= uid,
        .gid = sys::IdentityProvider::getGID(uid),
        .game_name = entry->binary.filename().string(),
        .envp = sys::IdentityProvider::getUserEnvironment(uid),
        .argv = { entry->binary.string() }
    });

    return true;
}

void GLauncher::launch(const LContext &ctx) {
    struct clone_args cl_args = {};
    cl_args.exit_signal = SIGCHLD;
    cl_args.flags = CLONE_INTO_CGROUP;
    cl_args.cgroup = static_cast<uint64_t>(ctx.cg.get_fd());
    
    uid_t uid = ctx.uid;
    gid_t gid = ctx.gid;

    // Prepare argv: [game_name, bin_path, ...args]
    std::vector<std::string> final_args = ctx.argv;
    final_args.insert(final_args.begin(), ctx.game_name);

    const std::vector<char*> argv = CInterop::toCStringVector(final_args);
    const std::vector<char*> envp = CInterop::toCStringVector(ctx.envp);

    long result = ::syscall(SYS_clone3, &cl_args, sizeof(cl_args));

    if (result == -1) {
        std::cerr << "Kernel rejected clone3! " << std::strerror(errno) 
                  << " (Code: " << errno << ")" << std::endl;
        return;
    }

    if (result == 0) {
        // We are in the CHILD
        ::prctl(PR_SET_PDEATHSIG, SIGKILL);

        // Security Lockdown
        using LauncherStatus = common::LauncherStatus;
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

    this->gpid = static_cast<pid_t>(result);
}

void GLauncher::start() {
    if (this->ctx.has_value()) {
        this->launch(*this->ctx);
    }
}

void GLauncher::stop() {
    this->gpid = -1;
    this->ctx.reset();
}

const LContext* GLauncher::getSessionInfo() const {
    return this->ctx ? &(*this->ctx) : nullptr;
}

} // namespace Launcher

