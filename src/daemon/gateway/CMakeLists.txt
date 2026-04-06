set(ODIN_GATEWAY_SOURCES CommandListener.cpp)

add_library(odin_gateway STATIC ${ODIN_GATEWAY_SOURCES})

target_include_directories(odin_gateway
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(
  odin_gateway
  PRIVATE sys_core
  PUBLIC project_headers)
