add_executable(unit_tests unit_tests.cpp)



target_link_libraries(unit_tests 
    PRIVATE 
        Catch2::Catch2WithMain
        System
)

catch_discover_tests(unit_tests
    EXTRA_ARGS -r compact
)
