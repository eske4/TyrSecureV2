#include "EnvironmentValidator.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <optional>
#include <vector>
#include <unordered_set>
#include <sstream>
#include <array>

namespace fs = std::filesystem;

namespace System::Environment
{

    bool Validator::isSecureBootEnabled()
    {
        const std::string path = "/sys/firmware/efi/efivars/";
        std::string secureBootFilePath;

        if (!fs::exists(path))
        {
            return false;
        }

        for (const auto &entry : fs::directory_iterator(path))
        {
            const auto &filename = entry.path().filename().string();

            if (filename.rfind("SecureBoot-", 0) == 0)
            {
                secureBootFilePath = entry.path().string();
                break;
            }
        }

        if (secureBootFilePath.empty())
        {
            return false;
        }

        std::ifstream secureBootFile(secureBootFilePath, std::ios::binary);

        if (!secureBootFile.is_open())
        {
            return false;
        }

        char byte;
        uint8_t lastByte = 0;

        while (secureBootFile.get(byte))
        {
            lastByte = static_cast<unsigned char>(byte);
        }

        return lastByte == 1;
    }

    bool Validator::isKernelLockdownEnabled()
    {
        const std::string lockdownPath = "/sys/kernel/security/lockdown";
        std::ifstream lockdownFile(lockdownPath);

        if (!lockdownFile.is_open())
        {
            return false;
        }

        std::string lockdownStatus;
        std::getline(lockdownFile, lockdownStatus);

        if (lockdownStatus.find("[confidentiality]") != std::string::npos)
        {
            return true;
        }

        return false;
    }

    bool Validator::isValid()
    {
        bool secureBootEnabled = isSecureBootEnabled();
        bool kLockdownEnabled = isKernelLockdownEnabled();

        bool valid = true;

        if (!secureBootEnabled)
        {
            std::cout << "Error: Secure Boot is not enabled." << std::endl;
            valid = false;
        }

        if (!kLockdownEnabled)
        {
            std::cout << "Error: Kernel lockdown(Confidential Mode) is not enabled." << std::endl;
            valid = false;
        }

        return true;
    }
}