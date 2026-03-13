#pragma once

#include <vector>
#include <string>
#include <sys/types.h>

namespace sys {

class SessionManager {
public:
    SessionManager() = default;

    static uid_t getUID();
    static gid_t getGID(uid_t uid);
    static std::vector<std::string> getUserEnvironment(uid_t uid);
    static void printEnvironment(std::vector<std::string> env, uid_t uid);
};

}
