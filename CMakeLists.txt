cmake_minimum_required(VERSION 4.3.0)

project(
  OdinSight
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "An anticheat focused on eBPF")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

include(Build)
include(Environment)
include(CPMConfig)
include(CPM)
include(Packages)
include(Compiler)
include(BPF)

set(GLOBAL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(ebpf)
add_subdirectory(src)
add_subdirectory(app)

option(BUILD_TESTING "Build the testing suite" OFF)

if(BUILD_TESTING)
  include(Tests)
  add_subdirectory(tests)
endif()
