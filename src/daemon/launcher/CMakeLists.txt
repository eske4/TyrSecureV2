set(LAUNCHER_SOURCES 
    CGManager.cpp 
    GLauncher.cpp 
    SessionManager.cpp
)

add_library(Launcher ${LAUNCHER_SOURCES})

target_include_directories(Launcher 
    PUBLIC "${GLOBAL_INCLUDE_DIR}"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
