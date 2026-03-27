set(SYSTEM_CORE_SOURCES CGroupService.cpp IdentityService.cpp EPollManager.cpp
                        EPollBinding.cpp)

add_library(sys_core ${SYSTEM_CORE_SOURCES})

target_include_directories(
  sys_core
  PUBLIC "${GLOBAL_INCLUDE_DIR}"
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
