set(CONTROL_SOURCES CommandListener.cpp)

add_library(Control ${CONTROL_SOURCES})

target_include_directories(
  Control
  PRIVATE "${GLOBAL_INCLUDE_DIR}"
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(Control PRIVATE System)
