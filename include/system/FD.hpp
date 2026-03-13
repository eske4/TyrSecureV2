#pragma once

#include <fcntl.h>
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
            open(path.c_str(), flags, mode);
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
    
        bool open(const char* path, int flags, mode_t mode = 0) {
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
    
        int release() {
            return std::exchange(fd, -1);
        }
    
        // Accessors
        bool isValid() const { return fd >= 0; }
        int get() const      { return fd; }
    
        // Operators
        operator int() const           { return fd; }
        explicit operator bool() const { return isValid(); }
    
    private:
        int fd = -1;
    };
}

