set(ODIN_EXECUTION_SOURCES Runner.cpp GameWhitelist.cpp)

add_library(odin_execution STATIC ${ODIN_EXECUTION_SOURCES})

target_include_directories(odin_execution
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(
  odin_execution
  PRIVATE sys_core
  PUBLIC project_headers)
