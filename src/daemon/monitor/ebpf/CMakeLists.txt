add_subdirectory(hooks)

set(EBPF_SOURCES 
    EbpfManager.cpp
    modules/SyscallModule.cpp
)

add_library(Ebpf ${EBPF_SOURCES})

add_dependencies(Ebpf ebpf_targets)

target_include_directories(Ebpf 
    PRIVATE "${GLOBAL_INCLUDE_DIR}"
    PUBLIC ${CMAKE_BINARY_DIR}/skeletons
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/modules
)

target_link_libraries(Ebpf 
    PRIVATE System
    PRIVATE ${LIBBPF_LIBRARIES}
)

