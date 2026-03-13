#pragma once

#include "daemon/LContext.hpp"

#include <optional>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/types.h>

namespace Launcher {
    enum class LauncherStatus : int {
            Success            = 0,
            SetGroupsFailed    = 100,
            SetGidFailed       = 101,
            SetUidFailed       = 102,
            ChdirFailed        = 103,
            NoNewPrivsFailed   = 104,
            SetDumpableFailed  = 105,
            ExecveFailed       = 106
    };
    
    class GLauncher {
    public:
        GLauncher() = default;
        ~GLauncher() { stop(); }
    
        GLauncher(const GLauncher&) = delete;
        GLauncher& operator=(const GLauncher&) = delete;
        GLauncher(GLauncher&&) = delete;
        GLauncher& operator=(GLauncher&&) = delete;
    
        /**
         * @brief Prepares the environment for the launcher.
         * @param bin_path Path to the executable.
         * @param game_root_dir Path to the working directory.
         * @param cgroup_name The name/path for the new CGroup.
         */
        void setup(const std::filesystem::path &bin_path,
                     const std::filesystem::path &game_working_dir_path,
                     const sys::CGroup& cgroup_parent);
        void start();
        void stop();
    
        bool isActive() const { return ctx.has_value() && gpid != -1; }
        bool isPrepared() const { return ctx.has_value() && gpid == -1; }
        pid_t getGpid() const { return gpid; }
        const LContext* getSessionInfo() const;
    
    private:
    
        /**
         * @brief The internal syscall logic (clone3/fexecve).
         * @param target_ctx The local context prepared by start().
         */
        void launch(const LContext &ctx);
        std::optional<LContext> ctx;
        pid_t gpid = -1;
    };
}
