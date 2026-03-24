set(EBPF_INTERNAL_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules
    ${CMAKE_BINARY_DIR}/skeletons
)
add_subdirectory(hooks)

set(EBPF_SOURCES 
    EbpfManager.cpp
    modules/SyscallModule.cpp
)

add_library(Ebpf ${EBPF_SOURCES})

add_dependencies(Ebpf generate_ebpf_skeletons)

target_include_directories(Ebpf 
    PRIVATE "${GLOBAL_INCLUDE_DIR}"
    PUBLIC ${EBPF_INTERNAL_INCLUDES}
)

target_link_libraries(Ebpf 
    PRIVATE System
    PRIVATE ${LIBBPF_LIBRARIES}
)

