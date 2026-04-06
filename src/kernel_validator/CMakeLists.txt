set(LAUNCHER_SOURCES
    EnvironmentValidator.cpp
    probes/UnsignedKernelModuleProbe.cpp
)

add_library(environment_validator ${LAUNCHER_SOURCES})

target_include_directories(environment_validator
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(environment_validator PRIVATE sys_core PUBLIC project_headers)
