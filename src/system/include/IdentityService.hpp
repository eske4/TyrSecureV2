#pragma once

#include <vector>
#include <string>
#include <sys/types.h>

namespace sys{

class IdentityService {
public:
    IdentityService() = default;

    [[nodiscard]] static uid_t getUID();
    [[nodiscard]] static gid_t getGID(uid_t uid);
    [[nodiscard]] static std::vector<std::string> getUserEnvironment(uid_t uid);
    static void printEnvironment(std::vector<std::string> env, uid_t uid);
};

}
