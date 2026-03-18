#pragma once

#include <cstdint>

static constexpr uint64_t MAGIC_VAL = 0x5459524553454355;

enum class EPollError : uint8_t {
    Interrupted = 0,
    SysCallFailed = 1,
    Timeout = 2,
    InvalidFD = 3
};

struct EPollBinding {
    using Handler = void(*)(void* context, uint32_t events);
    
    uint64_t magic = MAGIC_VAL;
    void* context; // The 'this' pointer of the owner object 
    bool active = true;
    Handler on_event;  // The static function that casts and calls the owner
                       //
    // Prevents Use-After-Free (UAF) if an event arrives for a deleted object.
    ~EPollBinding() {
        magic = 0; 
        active = false;
        on_event = nullptr;
    }

    // Prevents "Blind Jumps" if an attacker manages to swap heap memory or perform a heap spray
    bool isValid() const {
        return (magic == MAGIC_VAL) && (on_event != nullptr) && active;
    }
};
