add_executable(${PROJECT_NAME}_socket main.cpp)

target_link_libraries(
  ${PROJECT_NAME}_socket PRIVATE ebpf_manager daemon_launcher sys_core
                                 ebpf_modules daemon_control)
