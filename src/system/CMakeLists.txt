set(SYSTEM_CORE_SOURCES CGroupService.cpp IdentityService.cpp EPollManager.cpp)

add_library(sys_core ${SYSTEM_CORE_SOURCES})

target_include_directories(sys_core
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(sys_core PUBLIC project_headers)
