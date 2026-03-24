set(LAUNCHER_SOURCES Runner.cpp GameWhitelist.cpp)

add_library(Launcher ${LAUNCHER_SOURCES})

target_include_directories(
  Launcher
  PRIVATE "${GLOBAL_INCLUDE_DIR}"
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(Launcher PRIVATE System)
