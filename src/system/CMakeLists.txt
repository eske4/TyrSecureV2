set(LAUNCHER_SOURCES 
    CGService.cpp 
    IdentityService.cpp
    EPollManager.cpp
    EPollBinding.cpp
)

add_library(System ${LAUNCHER_SOURCES})

target_include_directories(System 
    PUBLIC "${GLOBAL_INCLUDE_DIR}"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
