add_executable(${PROJECT_NAME}_epoll main.cpp)

target_include_directories(${PROJECT_NAME}_epoll
                           PRIVATE "${GLOBAL_INCLUDE_DIR}")

target_link_libraries(${PROJECT_NAME}_epoll PRIVATE daemon_launcher sys_core
                                                    ebpf_manager ebpf_modules)
