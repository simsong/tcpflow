# Configuraion of the Coverage build
# Also adds targets to generate coverage repports

# Process this file only if BUILD_TYPE is "Coverage"
if( NOT CMAKE_BUILD_TYPE STREQUAL "Coverage" )
    return()
endif()

# This file support coverage only for GCC and Clang compilers
if( NOT CMAKE_COMPILER_IS_GNUCXX AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" )
    message(WARNING "<coverage.cmake> Coverage not yet implemented for your compiler '${CMAKE_CXX_COMPILER_ID}' (only GNU and Clang)")
    return()
endif()

# The function assert() may introduce a bias in covered lines count
# To ignore lines about assert() => Disable assert()
add_definitions(-DNDEBUG)

# Compilers GCC and Clang need flag --coverage
# Flag --coverage is a synonym for -fprofile-arcs -ftest-coverage (when compiling) and -lgcov (when linking)
# See https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html#index-g_t_0040command_007bgcov_007d-938
add_compile_options( --coverage )
link_libraries(      --coverage )

# Depending on presence of tools gcov/gcovr/lcov/genhtml => Add targets
# HTML report:
# - gcovr --root . --html --html-details --output coverage.html --exclude-unreachable-branches --print-summary
# - lcov + genhtml

find_program (gcov gcov)
if (NOT gcov)
    message(WARNING "<coverage.cmake> Cannot find gcov => Build may fail...")
endif()

find_program (gcovr gcovr)
if (gcovr)
    message (STATUS "<coverage.cmake> Found command 'gcovr' => Use target 'gcovr' to generate coverage report '${CMAKE_BINARY_DIR}/gcovr.html'")
    add_custom_target (gcovr
        COMMAND ${gcovr} --root             ${CMAKE_SOURCE_DIR}
                         --exclude          ${CMAKE_SOURCE_DIR}/3rdparty
                         --exclude          ${CMAKE_BINARY_DIR}
                         --object-directory ${CMAKE_BINARY_DIR}
                         --output           ${CMAKE_BINARY_DIR}/gcovr.html
                         --html
                         --html-details
                         --sort-uncovered
                         --print-summary
                         --exclude-unreachable-branches
        COMMAND echo "<coverage.cmake> To display coverage report: firefox ${CMAKE_BINARY_DIR}/gcovr.html"
    )
else()
    message(WARNING "<coverage.cmake> Cannot find command 'gcovr' => Please install package 'gcovr' to generate code coverage report (HTML)")
endif()

find_program (lcov    lcov   )
find_program (genhtml genhtml)
if (lcov AND genhtml)
    message (STATUS "<coverage.cmake> Found commands 'lcov' and 'genhtml' => Use target 'lcov' to generate coverage report '${CMAKE_BINARY_DIR}/lcov/index.html'")
    add_custom_target (lcov
        COMMAND ${lcov}    --capture     --directory     ${CMAKE_BINARY_DIR}
                           --no-external --output-file   ${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}-all.info
                           --no-checksum --base-directory ${CMAKE_SOURCE_DIR}
                           --rc    lcov_branch_coverage=1 --quiet
        COMMAND ${lcov}    --remove ${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}-all.info
                                            ${CMAKE_SOURCE_DIR}/*/test/*
                                            ${CMAKE_SOURCE_DIR}/*/*/test/*
                                            ${CMAKE_SOURCE_DIR}/*/*/*/test/*
                           --rc    lcov_branch_coverage=1
                           --output-file   ${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.info
        COMMAND ${genhtml} --rc genhtml_branch_coverage=1 ${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.info
                           --output-directory             ${CMAKE_BINARY_DIR}/lcov
                           --highlight --legend --quiet
        COMMAND echo "<coverage.cmake> To display coverage report: firefox ${CMAKE_BINARY_DIR}/lcov/index.html"
    )
else()
    message(WARNING "<coverage.cmake> Cannot find both commands 'lcov' and 'genhtml' => Please install package 'lcov' to generate code coverage report (HTML)")
endif()
