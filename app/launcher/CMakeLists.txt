add_executable(${PROJECT_NAME}_launcher main.cpp)

target_link_libraries(${PROJECT_NAME}_launcher PRIVATE project_headers
                                                       odin_gateway sys_core)
