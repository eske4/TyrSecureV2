add_executable(${PROJECT_NAME}_daemon main.cpp)

target_link_libraries(${PROJECT_NAME}_daemon PRIVATE odin_engine
    project_headers environment_validator)
