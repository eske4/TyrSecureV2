#pragma once

namespace common {

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

}

