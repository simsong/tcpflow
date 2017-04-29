# Default options and popular parameters

## CMAKE_BUILD_TYPE ##
# * Release (default) = -O2 + disable assert (-DNDEBUG)
# * Debug             = -O0 + enable  assert
# * Coverage          = -O0 + disable assert (-DNDEBUG)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "Coverage") # For 'cmake -i' and 'cmake-gui'
    message(STATUS "<options.cmake> CMAKE_BUILD_TYPE not set => Use value '${CMAKE_BUILD_TYPE}'.")
endif()

# Use "cmake -DSANITIZE=address" to enable Address sanitizer
# Use "cmake -DSANITIZE=thread"  to enable Thread  sanitizer
# Use "cmake -DSANITIZE=memory"  to enable Memory  sanitizer
# Use "cmake -DSANITIZE=dataflow" for DataFlowSanitizer
# Use "cmake -DSANITIZE=cfi" for control flow integrity checks (requires -flto)
# Use "cmake -DSANITIZE=safe-stack" for safe stack protection against stack-based memory corruption errors.
if(NOT SANITIZE)
    set(SANITIZE "OFF" CACHE STRING "Enable Address/Thread/Memory sanitizer.")
    set_property(CACHE SANITIZE PROPERTY STRINGS "OFF" "address" "thread" "memory" "dataflow" "cfi" "safe-stack" "multi")
    message(STATUS "<options.cmake> No SANITIZE (argument -DSANITIZE) => Set default value SANITIZE='${SANITIZE}'")
endif()
#option(SANITIZE "Sanity check" OFF)

# Use "cmake -DMARCH=native" to detect your current cpu-type 'xxx' and use it as -march=xxx
# Use another "-DMARCH=xxxx" to set a specific flag -march=xxx
# Default is "-DMARCH=corei7" on x86 architecture
set(MARCH "corei7" CACHE STRING "Control flag -march")
# Default produce -march=corei7
# To override use for example:    cmake .. -DMARCH=native (if native => convert to real )
# To disable provide empty value: cmake .. -DMARCH=

# Control flags -O0 -O1 -O2 -O3 -Ofast -Os -Og
set(OPTIM "" CACHE STRING "Control flags -Ox")

# For clang-check
set(CMAKE_EXPORT_COMPILE_COMMANDS "on")

# For user tooling (ex: YouCompleteMe)
#TODO FIXME configure_file(${CMAKE_CURRENT_LIST_DIR}/templates/BuildConfig.json.in ${RootDistDir}/dist/${SubDistDir}/BuildConfig.json)

# Colorize output: "always" or "auto" ("auto" colorizes if output is TTY)
if (ENV{BUILD_COLOR})
    option(BUILD_COLOR "Enable colored output for make and compiler" $ENV{BUILD_COLOR})
else()
    option(BUILD_COLOR "Enable colored output for make and compiler" always)
endif()

if (BUILD_COLOR)
    add_compile_options (-fdiagnostics-color=${BUILD_COLOR})
endif()

# Static code analysis
# Below line will enable the file 'compile_commands.json' to be used with clang-check
# Usage: awk -F: '/"file"/{print $2 }' build/compile_commands.json | xargs clang-check -fixit -p build
set(CMAKE_EXPORT_COMPILE_COMMANDS "on")
