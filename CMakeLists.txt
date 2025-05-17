# Minimum required version of CMake
# This ensures compatibility with features used in this file.
cmake_minimum_required(VERSION 3.10)

# Project name
# This sets the name of your project.
project(myapp VERSION 1.0)

# Set the C++ standard
# It's good practice to explicitly set the C++ standard you want to use.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS True) # Optional: turn off compiler extensions

set(CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  # for in-fbsource builds
  "${CMAKE_CURRENT_SOURCE_DIR}/../opensource/fbcode_builder/CMake"
  # For shipit-transformed builds
  "${CMAKE_CURRENT_SOURCE_DIR}/build/fbcode_builder/CMake"
  ${CMAKE_MODULE_PATH})

find_package(Folly REQUIRED)
find_package(gflags REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

find_package(proxygen REQUIRED)

# --- Debugging: Print gflags related variables ---
# message(STATUS "--- Debugging gflags variables ---")
# get_cmake_property(_variableNames VARIABLES)
# foreach (_variableName ${_variableNames})
#     if ("${_variableName}" MATCHES "^GFLAGS_.*" OR "${_variableName}" MATCHES "gflags")
#         message(STATUS "${_variableName}=${${_variableName}}")
#     endif()
# endforeach()
# message(STATUS "--- End Debugging gflags variables ---")

# --- Debugging: Print defined targets ---
message(STATUS "--- Debugging defined targets ---")
get_cmake_property(_allTargets TARGETS)
foreach(_target ${_allTargets})
    # Filter for targets that might be related to gflags
    if ("${_target}" MATCHES "gflags")
        message(STATUS "Defined target: ${_target}")
    endif()
endforeach()
message(STATUS "--- End Debugging defined targets ---")

# Define the source files for your application
# List all your .cpp files here.
# set(SOURCE_FILES
#     src/main.cpp
# )

# Add include directories
# If your project uses header files that are not in the same directory as the source files,
# add their directories here. Use relative or absolute paths.
# include_directories(
#     include {CMAKE_SOURCE_DIR}/src
#     # Add other include paths if necessary, e.g., for external libraries
#     # /path/to/external/library/include
# )

# Add an executable target
# This tells CMake to create an executable.
# The first argument is the name of the executable, and the following argumen   ts are the source files.
add_executable(webapp)

target_link_directories(webapp PUBLIC ${GFLAGS_LIB_DIR})

target_link_libraries(webapp PUBLIC
    #gflags::gflags
    ${GFLAGS_LIBRARIES}
    Folly::folly
    proxygen::proxygenhttpserver
)
 
# Link libraries to the executable (if needed)
# If your application depends on external libraries (like Boost, custom libraries, etc.),
# link them here.
# target_link_libraries(my_app my_library another_library)

# Optional: Install rules
# Define where to install the executable and other files (like headers, libraries).
install(TARGETS webapp DESTINATION bin)
#install(DIRECTORY include/ DESTINATION include)

# Optional: Add unit tests
# If you are using a testing framework like Google Test, you can add test targets here.
# enable_testing()
# add_subdirectory(tests) # Assuming your tests are in a 'tests' subdirectory
add_subdirectory(src)