cmake_minimum_required(VERSION 3.25.1)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Enforce Linux
project(
  TyrSecure
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "An anticheat focused on eBPF")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

add_compile_options(-Wall -Wextra)

include(Build)
include(Environment)
include(CPM)
include(Packages)
include(Compiler)
include(BPF)

set(GLOBAL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

option(BUILD_TESTING "Build the testing suite" OFF)

if(BUILD_TESTING)
    message(STATUS "Testing is enabled")
    CPMAddPackage(gh:catchorg/Catch2@3.13.0)
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(CTest)
    include("${Catch2_SOURCE_DIR}/extras/Catch.cmake")
    enable_testing()
    add_subdirectory(tests)
endif()

add_subdirectory(src)
add_subdirectory(app)
