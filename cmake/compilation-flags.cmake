# This files sets the compiler/linker flags
# Supported compilers: GCC and Clang


# Use distcc/ccache if available
# TODO(olibre): Use "CMAKE_{C,CXX}_COMPILER_LAUNCHER=ccache" with cmake-v3.4
find_program(path_distcc distcc)
find_program(path_ccache ccache)
if(path_ccache AND path_distcc)
    message(STATUS "<compilation-flags.cmake> Commands 'distcc' and 'ccache' detected => Use 'distcc' and 'ccache' to speed up build" )
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "env CCACHE_PREFIX=distcc")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK    "env CCACHE_PREFIX=distcc")
elseif(path_ccache)
    message(STATUS "<compilation-flags.cmake> Command 'ccache' detected => Use 'ccache' to speed up compilation and link")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK    ccache)
elseif(path_distcc)
    message(STATUS "<compilation-flags.cmake> Command 'distcc' detected => Use 'distcc' to speed up compilation and link")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE distcc)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK    distcc)
endif()


if(NOT CMAKE_COMPILER_IS_GNUCXX AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(STATUS "<compilation-flags.cmake> Rest of compiler/linker flags are not available for your C++ compiler '${CMAKE_CXX_COMPILER_ID}' (only GNU and Clang are supported for the moment, please help extend these flags for your tools)")
    return()
endif()


if (BUILD_COLOR)
    message(STATUS "<compilation-flags.cmake> Detected defined BUILD_COLOR => Use -fdiagnostics-color=${BUILD_COLOR}")
    add_compile_options (-fdiagnostics-color=${BUILD_COLOR})
    link_libraries      (-fdiagnostics-color=${BUILD_COLOR})
endif()


# -g3 => Max debug info for all targets (for any CMAKE_BUILD_TYPE)
# Replace -g3 by -g2 if produced binaries are too big
# Binaries may also be stripped (at packaging stage) to remove debug info
add_compile_options(-g3) # -g3 -> include also the MACRO definitions


# Compilation flag -march
if(MARCH STREQUAL "native")
    if(CMAKE_COMPILER_IS_GNUCXX)
        EXECUTE_PROCESS( COMMAND ${CMAKE_CXX_COMPILER} -march=native -Q --help=target COMMAND awk "/-march=/{ printf $2}" OUTPUT_VARIABLE march_native )
        message(STATUS "<compilation-flags.cmake> MARCH is native and compiler is GNU => Detected processor '${march_native}' => -march=${march_native}")
        add_compile_options( -march=${march_native} )
    else()
        message(STATUS "<compilation-flags.cmake> MARCH is native and compiler is *not* GNU => -march=native")
        add_compile_options( -march=native )
    endif()
elseif( MARCH )
    message(STATUS "<compilation-flags.cmake> MARCH is not native => -march=${MARCH}")
    add_compile_options( -march=${MARCH} )
else()
    message(STATUS "<compilation-flags.cmake> MARCH is empty => Do not set flag -march")
endif()


#  # Speed up build using pipes (rather than temporary files) for communication between the various GCC stages
#  add_compile_options(-pipe)
#  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pipe")
#  TODO(olibre): Command link_libraries(-pipe) may be use instead of above line (why not?)



# Optimization flag
# Set -O0/-Og/-O1/-O2/-O3/-Ofast depending on CMAKE_BUILD_TYPE
if(OPTIM STREQUAL "default")
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        message(STATUS "<compilation-flags.cmake> OPTIM=${OPTIM} and CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} => -02")
        add_compile_options(-O2)
    else()
        message(STATUS "<compilation-flags.cmake> OPTIM=${OPTIM} and CMAKE_BUILD_TYPE!='Release' => -O0 -fno-inline")
        add_compile_options(-O0 -fno-inline)
    endif()
elseif(OPTIM)
    message(STATUS "<compilation-flags.cmake> OPTIM!='default' => Add content of OPTIM=${OPTIM} in compiler flags")
    add_compile_options(${OPTIM})
endif()


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "<compilation-flags.cmake> CMAKE_BUILD_TYPE='${CMAKE_BUILD_TYPE}' => Add -D_GLIBCXX_DEBUG_PEDANTIC in compiler flags")
    add_definitions(-D_GLIBCXX_DEBUG_PEDANTIC)
endif()

# Instrument the produced libraries/executables for run-time analysis
if(SANITIZE STREQUAL "multi")
    message(STATUS "<compilation-flags.cmake> Detected SANITIZE='${SANITIZE}' => Add '-fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=signed-integer-overflow -fsanitize=shift -fsanitize=integer-divide-by-zero -fsanitize=null' in compiler flags")
    add_compile_options(-fsanitize=address -fsanitize=leak -fsanitize=undefined -fsanitize=signed-integer-overflow -fsanitize=shift -fsanitize=integer-divide-by-zero -fsanitize=null)
elseif(SANITIZE)
    message(STATUS "<compilation-flags.cmake> Detected SANITIZE is enable but not 'multi' => Add '-fsanitize=${SANITIZE}' in compiler flags")
    add_compile_options(-fsanitize=${SANITIZE})
endif()
