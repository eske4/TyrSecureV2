# List of BPF programs
set(EBPF_PROGRAMS daemon_hardener.bpf.c master.bpf.c print_test.bpf.c)

# Where skeleton headers go
set(VMLINUX_DIR ${CMAKE_SOURCE_DIR}/ebpf/include)
set(SKEL_OUT_DIR ${CMAKE_SOURCE_DIR}/ebpf/skeletons)
file(MAKE_DIRECTORY ${SKEL_OUT_DIR})

# Mark programs as C for LSP/clangd
set_source_files_properties(${EBPF_PROGRAMS} PROPERTIES LANGUAGE C)

# Compile BPF programs into an OBJECT library
add_library(ebpf_targets OBJECT ${EBPF_PROGRAMS})
target_include_directories(ebpf_targets PRIVATE ${VMLINUX_DIR})
target_link_libraries(ebpf_targets PRIVATE bpf_headers)
target_compile_options(
  ebpf_targets
  PRIVATE -target
          bpf
          -O2
          -g
          -x
          c
          -std=gnu17
          -Wno-unused-parameter
          -Wno-missing-declarations
          -D__TARGET_ARCH_x86)

# ------------------------------
# Generate skeletons for each BPF program
# ------------------------------
set(SKEL_HEADERS "")

foreach(src ${EBPF_PROGRAMS})
  get_filename_component(name ${src} NAME_WE) # remove .bpf.c
  set(SKEL_H "${SKEL_OUT_DIR}/${name}.skel.h")

  # Use CMake's OBJECT library output
  set(OBJ_FILE "$<TARGET_OBJECTS:ebpf_targets>")
  set(OBJ_FILE_EXPR
      "$<FILTER:$<TARGET_OBJECTS:ebpf_targets>,INCLUDE,${name}\\.bpf\\.c\\.o$>")

  add_custom_command(
    OUTPUT ${SKEL_H}
    COMMAND bpftool gen skeleton ${OBJ_FILE_EXPR} name ${name} > ${SKEL_H}
    DEPENDS ebpf_targets
    VERBATIM
    COMMENT "--> Generating skeleton: ${name}")

  list(APPEND SKEL_HEADERS ${SKEL_H})
endforeach()
# Master target to build all skeletons
add_custom_target(generate_ebpf_skeletons ALL DEPENDS ${SKEL_HEADERS})
