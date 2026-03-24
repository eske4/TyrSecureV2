cmake_minimum_required(VERSION 3.25.1)

set(CPM_SOURCE_CACHE
    "$ENV{HOME}/.cache/CPM"
    CACHE PATH "CPM source cache")
message(STATUS "CPM Source Cache set to: ${CPM_SOURCE_CACHE}")

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Enforce Linux
project(
  TyrSecure
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "An anticheat focused on eBPF")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

include(Build)
include(Environment)
include(CPM)
include(Packages)
include(Compiler)
include(BPF)

set(GLOBAL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

option(BUILD_TESTING "Build the testing suite" ON)

if(BUILD_TESTING)
  include(Tests)
  add_subdirectory(tests)
endif()

add_subdirectory(src)
add_subdirectory(app)
