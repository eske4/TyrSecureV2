set(DAEMON_CONTROL_SOURCES CommandListener.cpp)

add_library(daemon_control ${DAEMON_CONTROL_SOURCES})

target_include_directories(
  daemon_control
  PRIVATE "${GLOBAL_INCLUDE_DIR}"
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(daemon_control PRIVATE sys_core)
