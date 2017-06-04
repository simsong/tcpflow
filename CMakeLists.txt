cmake_minimum_required(VERSION 3.1)

project(tcpflow VERSION 1.4.6 LANGUAGES CXX C)
# Within the above line, "C" is required for two reasons:
# 1. find_package(Threads) fails using only CXX on cmake-3.3 and previous
# 2. CMake files use CMAKE_C_COMPILER_ID instead of CMAKE_CXX_COMPILER_ID

# The following line if for find_package(pcap) -> cmake/FindPCAP.cmake
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(cmake/options.cmake)             # Set default CMake options
include(cmake/coverage.cmake)            # Configure the build "Coverage"
include(cmake/compilation-flags.cmake)   # Compiler & Linker flags
include(cmake/warning-flags.cmake)       # Compiler & Linker warnings

# Source code
add_subdirectory(src)

# Generate documentation
#add_subdirectory( doc EXCLUDE_FROM_ALL )

