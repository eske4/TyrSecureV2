add_executable(${PROJECT_NAME}_launcher main.cpp)

target_include_directories(${PROJECT_NAME}_launcher 
    PRIVATE "${GLOBAL_INCLUDE_DIR}"
)
