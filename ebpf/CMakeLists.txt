# Ensure skeletons folder exist
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/ebpf/skeletons)

# Add hooks subdirectory so programs are compiled and skeletons generated
add_subdirectory(hooks)

# INTERFACE library for all BPF artifacts (headers + skeletons)
add_library(ebpf_interface INTERFACE)

# Include paths
target_include_directories(
  ebpf_interface
  INTERFACE ${CMAKE_SOURCE_DIR}/ebpf/include # shared headers
            ${CMAKE_SOURCE_DIR}/ebpf/skeletons # generated skeletons
)

# Ensure skeletons are generated before any module uses them
add_dependencies(ebpf_interface generate_ebpf_skeletons)
