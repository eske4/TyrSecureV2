#pragma once

#include "common/GameID.hpp"
#include "LContext.hpp"

#include <optional>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/types.h>

namespace Launcher {

    class GLauncher {

    public:

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

    private:
    
        /**
         * @brief The internal syscall logic (clone3/fexecve).
         * @param target_ctx The local context prepared by start().
         */
        void launch(const LContext &ctx);
        std::optional<LContext> m_ctx;
        pid_t m_gpid = -1;
    public:
        GLauncher() = default;
        ~GLauncher() { stop(); }
    
        GLauncher(const GLauncher&) = delete;
        GLauncher& operator=(const GLauncher&) = delete;
        GLauncher(GLauncher&&) = delete;
        GLauncher& operator=(GLauncher&&) = delete;
    
        /**
         * @brief Prepares the environment for the launcher.
         * @param game_id: Path to the executable.
         * @param cgroup: The parents cgroup.
         */
        [[nodiscard]] bool setup(const common::GameID &game_id,
                                 const sys::CGroup& cgroup_parent);
        void start();
        void stop();
    
        [[nodiscard]] bool isActive() const { return m_ctx.has_value() && m_gpid != -1; }
        [[nodiscard]] bool isPrepared() const { return m_ctx.has_value() && m_gpid == -1; }
        [[nodiscard]] bool canLaunch();
        [[nodiscard]] pid_t getGpid() const { return m_gpid; }
        [[nodiscard]] const LContext* getSessionInfo() const;
    
    };
}
