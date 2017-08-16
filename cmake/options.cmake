# Default options and popular parameters


# --------- CMAKE_BUILD_TYPE ----------
# * Release  = -O2 + disable assert (-DNDEBUG)
# * Debug    = -O0 + enable  assert              <-- Default value
# * Coverage = -O0 + disable assert (-DNDEBUG)
set(CMAKE_CONFIGURATION_TYPES Release Debug Coverage CACHE STRING "Reset the supported CMAKE_BUILD_TYPEs." FORCE)
# Use "cmake -DCMAKE_BUILD_TYPE=Release" or "cmake -DCMAKE_BUILD_TYPE=Coverage" to override default value 'Debug'
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "Coverage")
    message(STATUS "<options.cmake> CMAKE_BUILD_TYPE not set => Use default value '${CMAKE_BUILD_TYPE}'.")
endif()


# Use "cmake -DSANITIZE=address" to enable Address sanitizer
# Use "cmake -DSANITIZE=thread"  to enable Thread  sanitizer
# Use "cmake -DSANITIZE=memory"  to enable Memory  sanitizer
# Use "cmake -DSANITIZE=dataflow" for DataFlowSanitizer
# Use "cmake -DSANITIZE=cfi" for control flow integrity checks (requires -flto)
# Use "cmake -DSANITIZE=safe-stack" for safe stack protection against stack-based memory corruption errors.
# Use "cmake -DSANITIZE=multi" to combine some of them
if(NOT SANITIZE)
    set(SANITIZE "OFF" CACHE STRING "Enable Address/Thread/Memory sanitizer.")
    set_property(CACHE SANITIZE PROPERTY STRINGS "OFF" "address" "thread" "memory" "dataflow" "cfi" "safe-stack" "multi")
    message(STATUS "<options.cmake> SANITIZE not set (cmake -DSANITIZE=xxx) => Set default value SANITIZE='${SANITIZE}'")
endif()
#option(SANITIZE "Sanity check" OFF)

# Use "cmake -DMARCH=native" to detect your current cpu-type 'xxx' and CMake will convert to -march=xxx
# Use "cmake -DMARCH=zzzz" to set a specific flag -march=zzzz
# Default is "-DMARCH=corei7" (fine on x86 architecture)
# Use "cmake -DMARCH=   " (empty value) to disable flag -march
set(MARCH "corei7" CACHE STRING "Control flag -march")

# Control flags -O0 -O1 -O2 -O3 -Ofast -Os -Og
set(OPTIM "" CACHE STRING "Control flags -Ox")

# For clang-check
set(CMAKE_EXPORT_COMPILE_COMMANDS "on")


# Colorize output: "always" or "auto" ("auto" colorizes if output is TTY)
if (ENV{BUILD_COLOR})
    option(BUILD_COLOR "<options.cmake> Enable colored output for make and compiler" $ENV{BUILD_COLOR})
else()
    option(BUILD_COLOR "<options.cmake> Enable colored output for make and compiler" always)
endif()


# Static code analysis
# Below line is to generate the file 'compile_commands.json' during the build
# Then, the file 'compile_commands.json' can be used with clang-check using the below command line:
# awk -F: '/"file"/{print $2 }' build/compile_commands.json | xargs clang-check -fixit -p build
set(CMAKE_EXPORT_COMPILE_COMMANDS "on")


# For Tools like YouCompleteMe
# TODO(???): Provide BuildConfig.json.in
# configure_file(${CMAKE_CURRENT_LIST_DIR}/templates/BuildConfig.json.in ${CMAKE_CURRENT_BINARY_DIR}/BuildConfig.json)
