#include "SyscallModule.hpp"
#include <iostream>

    SyscallModule::SyscallModule(){}
    SyscallModule::~SyscallModule() {
        if (skel) print_test__destroy(skel);
    }

    bool SyscallModule::open() {
        skel = print_test__open();
        return skel != nullptr;
    }

    bool SyscallModule::load(int shared_rb_fd) {
        // CRITICAL: Tell this module to use the shared Ring Buffer FD 
        // instead of creating its own internal 'rb' map.
        if (shared_rb_fd >= 0) {
            bpf_map__reuse_fd(skel->maps.rb, shared_rb_fd);
        }

        return print_test__load(skel) == 0;
    }

    bool SyscallModule::attach() {
        return print_test__attach(skel) == 0;
    }

    void SyscallModule::process_event(const common::ebpf_event* event, size_t size) {
        // Logic to handle the specific event type for this module
        std::cout << "[" << get_name() << "] Event Type: " << event->event_type << event->timestamp << std::endl;
    }

    common::bpf_module_id_t SyscallModule::get_id() const {
        return common::bpf_module_id_t::MODULE_LSM_SHIELD; 
    }

    const char* SyscallModule::get_name() const { return name; }
