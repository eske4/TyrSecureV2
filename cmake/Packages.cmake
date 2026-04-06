# message(STATUS "======================================") message(STATUS "
# Checking required packages") message(STATUS
# "======================================")

# ---- Check for pkg-config ----
find_package(PkgConfig)

if(PkgConfig_FOUND)
  # message(STATUS "✅ pkg-config found")
else()
  message(
    FATAL_ERROR
      "\n❌ pkg-config not found.\n"
      "It is required to locate system libraries.\n\n" "Install it with:\n"
      "  Arch: sudo pacman -S pkgconf\n")
endif()

# ---- Check for libbpf ----
pkg_check_modules(LIBBPF libbpf>=0.7)

if(LIBBPF_FOUND)
  # message(STATUS "✅ libbpf found") message(STATUS "   Version   :
  # ${LIBBPF_VERSION}") message(STATUS "   Includes  : ${LIBBPF_INCLUDE_DIRS}")
  # message(STATUS "   Libraries : ${LIBBPF_LIBRARIES}")
else()
  message(FATAL_ERROR "\n❌ libbpf >= 0.7 not found (skeleton API required).\n"
                      "Install it with:\n" "  Arch: sudo pacman -S libbpf\n")
endif()

find_package(Catch2 3 QUIET)

if(BUILD_TESTING)
  if(NOT Catch2_FOUND)
    message(
      FATAL_ERROR
        "\n❌ BUILD_TESTING is ON, but Catch2 v3 was not found.\n"
        "Please install it with: sudo pacman -S catch2\n"
        "Or disable testing with: -DBUILD_TESTING=OFF\n")
  endif()
  message(STATUS "✅ Catch2 found - Testing suite enabled")
else()
  # Only warn if it's missing, just so they know why they can't enable tests
  # easily
  if(NOT Catch2_FOUND)
    message(STATUS "⚠️  Catch2 v3 not found (Tests remain unavailable)")
  endif()
endif()

# add packages here
