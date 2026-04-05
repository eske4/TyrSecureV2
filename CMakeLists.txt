cmake_minimum_required(VERSION 4.3.0)

project(
  OdinSight
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "An anticheat focused on eBPF")

# 1. Set paths first
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

# 1. Define Options BEFORE including Package/Test logic
option(BUILD_TESTING "Build the testing suite" OFF)

# 1. Core Environment & Compiler Setup
include(Build)
include(Environment)
include(Compiler)

include(CPMConfig)
include(CPM)
include(Packages)
include(BPF)

# 1. Global Headers
add_library(project_headers INTERFACE)
target_include_directories(project_headers
                           INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

# 1. Build Components
add_subdirectory(ebpf)
add_subdirectory(src)
add_subdirectory(app)

# 1. Testing Logic
if(BUILD_TESTING)
  include(Tests) # Should contain: include(CTest) and include(Catch)
  add_subdirectory(tests)
endif()
