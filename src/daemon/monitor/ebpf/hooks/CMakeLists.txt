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
          -Wno-missing-declarations
          -std=gnu17
          # This is the critical line for Kprobes:
          -D__TARGET_ARCH_x86)
          
# 1. Map skeletons to their specific object files

# 2. Map skeletons to their specific object files
set(SKEL_HEADERS "")

foreach(src ${EBPF_PROGRAMS})
    string(REGEX REPLACE "\\.bpf\\.c$" "" name ${src})
    set(SKEL_H "${SKEL_OUT_DIR}/${name}.skel.h")

    set(OBJ_FILE_EXPR "$<FILTER:$<TARGET_OBJECTS:ebpf_targets>,INCLUDE,${name}\\.bpf\\.c\\.o$>")

    add_custom_command(
        OUTPUT "${SKEL_H}"
        COMMAND bpftool gen skeleton "${OBJ_FILE_EXPR}" name "${name}" > "${SKEL_H}"
        DEPENDS ebpf_targets
        VERBATIM
        COMMENT "--> Generating skeleton: ${name}"
    )

    list(APPEND SKEL_HEADERS "${SKEL_H}")
endforeach()

# 3. Create ONE master target for all skeletons
add_custom_target(generate_ebpf_skeletons ALL DEPENDS ${SKEL_HEADERS})

