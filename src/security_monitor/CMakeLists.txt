set(LAUNCHER_SOURCES
    EnvironmentValidator.cpp
)

add_library(EnvironmentValidator ${LAUNCHER_SOURCES})

target_include_directories(EnvironmentValidator
    PUBLIC "${GLOBAL_INCLUDE_DIR}"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(EnvironmentValidator PRIVATE System)
