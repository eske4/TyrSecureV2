#pragma once

namespace System::Environment
{
    class Validator
    {
    private:
        static bool isSecureBootEnabled();
        static bool isKernelLockdownEnabled();

    public:
        static bool isValid();
    };
}