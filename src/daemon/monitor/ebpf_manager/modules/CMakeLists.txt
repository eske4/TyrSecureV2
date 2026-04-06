set(MODULE_SOURCES SyscallModule.cpp)

add_library(ebpf_modules STATIC ${MODULE_SOURCES})

target_include_directories(ebpf_modules
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Modules depend on ebpf_manager
target_link_libraries(ebpf_modules PRIVATE odin_ebpf)
