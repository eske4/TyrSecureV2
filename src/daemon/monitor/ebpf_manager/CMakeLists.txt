set(EBPF_SOURCES EbpfManager.cpp EbpfRingbufferListener.cpp)

add_library(odin_ebpf STATIC ${EBPF_SOURCES})

target_include_directories(odin_ebpf
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(
  odin_ebpf
  PUBLIC ebpf_interface project_headers
  PRIVATE sys_core
  PRIVATE ${LIBBPF_LIBRARIES})

add_subdirectory(modules)
