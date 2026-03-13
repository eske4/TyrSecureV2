#pragma once

#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace sys {

    class FD {
    public:
        FD() = default;
    
        // Direct initialization from path
        explicit FD(const std::string& path, int flags, mode_t mode = 0) {
            bool result = open(path.c_str(), flags, mode);
            if(!result){
                std::cout << "[ERROR] Failed to open file descriptor in FD object" << std::endl;
            }
        }
    
        // Wrap an existing raw descriptor
        explicit FD(int file_descriptor) : fd(file_descriptor) {}
    
        // Move logic using std::exchange for conciseness
        FD(FD&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
        
        FD& operator=(FD&& other) noexcept {
            if (this != &other) {
                reset();
                fd = std::exchange(other.fd, -1);
            }
            return *this;
        }
    
        // Disable copies
        FD(const FD&) = delete;
        FD& operator=(const FD&) = delete;
    
        ~FD() { reset(); }
    
        [[nodiscard]] bool open(const char* path, int flags, mode_t mode = 0) {
            reset();
            fd = ::open(path, flags | O_CLOEXEC, mode);
            return isValid();
        }
    
        void reset() {
            if (fd >= 0) {
                ::close(fd);
                fd = -1;
            }
        }
    
        [[nodiscard]] int release() {
            return std::exchange(fd, -1);
        }
    
        // Accessors
        [[nodiscard]] bool isValid() const { return fd >= 0; }
        [[nodiscard]] int get() const      { return fd; }
    
        // Operators
        operator int() const           { return fd; }
        explicit operator bool() const { return isValid(); }
    
    private:
        int fd = -1;
    };
}

