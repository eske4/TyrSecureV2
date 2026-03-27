set(DAEMON_LAUNCHER_SOURCES Runner.cpp GameWhitelist.cpp)

add_library(daemon_launcher ${DAEMON_LAUNCHER_SOURCES})

target_include_directories(
  daemon_launcher
  PRIVATE "${GLOBAL_INCLUDE_DIR}"
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(daemon_launcher PRIVATE sys_core)
