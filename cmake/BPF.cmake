# Directory to hold generated headers
set(BPF_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/ebpf/include)
set(VMLINUX_OUT ${BPF_INCLUDE_DIR}/vmlinux.h)

# Ensure include directory exists
file(MAKE_DIRECTORY ${BPF_INCLUDE_DIR})

# Check if vmlinux.h already exists
if(NOT EXISTS ${VMLINUX_OUT})
  message(STATUS "vmlinux.h not found, generating...")

  add_custom_command(
    OUTPUT ${VMLINUX_OUT}
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c >
            ${VMLINUX_OUT}
    WORKING_DIRECTORY ${BPF_INCLUDE_DIR}
    COMMENT "Generating vmlinux.h in ebpf/include/"
    VERBATIM)
else()
  message(STATUS "vmlinux.h already exists, skipping generation")
endif()

# Target that other libraries can depend on
add_custom_target(generate_vmlinux_h ALL DEPENDS ${VMLINUX_OUT})
