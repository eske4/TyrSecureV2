add_executable(${PROJECT_NAME}_daemon main.cpp)

target_link_libraries(${PROJECT_NAME}_daemon
    PRIVATE
    Launcher)
