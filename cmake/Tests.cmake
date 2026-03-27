# No need for the 'if(BUILD_TESTING)' here if you handle it in the caller
# but you can keep it for safety.

CPMAddPackage("gh:catchorg/Catch2@3.13.0")

# Fix the variable name confusion
if(Catch2_SOURCE_DIR)
    set(CATCH_EXTRAS "${Catch2_SOURCE_DIR}/extras")
else()
    set(CATCH_EXTRAS "${catch2_SOURCE_DIR}/extras")
endif()

list(APPEND CMAKE_MODULE_PATH "${CATCH_EXTRAS}")

include(CTest)
enable_testing()

# This pulls in 'catch_discover_tests'
include(Catch) 

# Note: I recommend moving 'add_subdirectory(tests)' to the main file 
# so you can see the project structure at a glance.

