add_executable(integration_tests integration_tests.cpp)

target_link_libraries(integration_tests 
    PRIVATE 
        Catch2::Catch2WithMain
        System
)

catch_discover_tests(integration_tests
    EXTRA_ARGS -r compact
)
