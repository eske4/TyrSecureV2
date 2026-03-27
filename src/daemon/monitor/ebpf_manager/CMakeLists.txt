set(EBPF_SOURCES EbpfManager.cpp)

add_library(ebpf_manager ${EBPF_SOURCES})

target_include_directories(
  ebpf_manager
  PRIVATE "${GLOBAL_INCLUDE_DIR}"
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(
  ebpf_manager
  PUBLIC ebpf_interface
  PRIVATE sys_core
  PRIVATE ${LIBBPF_LIBRARIES})

add_subdirectory(modules)
