set(EBPF_PROGRAMS master.bpf.c print_test.bpf.c)
# src/eBPF_prog/CMakeLists.txt
set_source_files_properties(${EBPF_PROGRAMS} PROPERTIES LANGUAGE C)

# 1. Keep the library so the LSP/clangd works
add_library(ebpf_targets OBJECT ${EBPF_PROGRAMS})
target_include_directories(ebpf_targets PRIVATE ${EBPF_INTERNAL_INCLUDES})
target_link_libraries(ebpf_targets PRIVATE bpf_headers)
target_compile_options(
  ebpf_targets
  PRIVATE -target
          bpf
          -O2
          -g
          -x
          c
          -Wno-unused-parameter
          -std=gnu17
          # This is the critical line for Kprobes:
          -D__TARGET_ARCH_x86)
          
# 1. Map skeletons to their specific object files
foreach(src ${EBPF_PROGRAMS})
    string(REPLACE ".bpf.c" "" name ${src})
    set(SKEL_H "${SKEL_OUT_DIR}/${name}.skel.h")
    
    # Path to the .o file - double check this matches your build folder!
    set(OBJ_FILE "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ebpf_targets.dir/${src}.o")

    add_custom_command(
        OUTPUT "${SKEL_H}"
        COMMAND bpftool gen skeleton "${OBJ_FILE}" name "${name}" > "${SKEL_H}"
        DEPENDS ebpf_targets "${OBJ_FILE}"
        VERBATIM
        COMMENT "--> Building skeleton: ${name}"
    )

    # Create the target, but DON'T use ALL
    add_custom_target(${name}_skel DEPENDS "${SKEL_H}")
endforeach()

