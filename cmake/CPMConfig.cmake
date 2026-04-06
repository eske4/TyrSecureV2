# Simple, Arch-centric cache setup
set(CPM_SOURCE_CACHE "$ENV{HOME}/.cache/CPM" CACHE PATH "CPM source cache")

# Only show the message once (during the initial configuration)
get_property(CACHE_LOGGED GLOBAL PROPERTY CPM_CACHE_LOGGED)
if(NOT CACHE_LOGGED)
    message(STATUS "CPM Cache: ${CPM_SOURCE_CACHE}")
    set_property(GLOBAL PROPERTY CPM_CACHE_LOGGED ON)
endif()
