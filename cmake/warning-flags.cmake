# Warning flags and Macro (#define)


# For the moment only support GCC and Clang
if(NOT CMAKE_COMPILER_IS_GNUCXX AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(STATUS "<warning-flags.cmake> No warning set for your compiler '${CMAKE_CXX_COMPILER_ID}' (only GNU and Clang are supported for the moment)")
    return()
endif()


# See http://stackoverflow.com/a/16604146/938111
add_definitions(-D_FORTIFY_SOURCE=2)


# Colorize output
if (BUILD_COLOR)
    add_compile_options(-fdiagnostics-color=${BUILD_COLOR})
endif()

# Clang specifics
if (CMAKE_C_COMPILER_ID STREQUAL Clang)
    add_compile_options(
        -Weverything
        -Wno-c++98-compat
        -Wno-c++98-compat-pedantic
    )
endif()

add_compile_options(
    -Wall                        # Classic warnings
    -Wextra                      # Extra amount of warnings
    -Weffc++                     # Books "Effective C++" from Scott Meyers
    -pedantic                    # Reject code not following ISO C++ (e.g. GNU extensions)
    -Winit-self                  # Variables initialized with themselves (enabled by -Wall)
    -Wswitch-enum                # Missing case for values of switch(enum)
    -Wswitch                     # Missing enumerated type in 'case' labels
    -Wcast-align                 # Incompatible alignment pointers
    -Wcast-qual                  # Cast between pointers leads to target type qualifier removal
    -Wconversion                 # Conversion might lead to value alteration, confusing overload resolution
    -Wsign-conversion
    -Wformat=2                   # Invalid argument types and format strings in formatting functions (printf, scanf...)
    -Wuninitialized              # Variable used without being initialized
    -Wmissing-field-initializers # Fields is left uninitialized during (non-designated) structure initialization
    -Wmissing-include-dirs       # User-supplied include directory does not exist
    -Wpointer-arith              # [void and function] Operations addition/subtraction/sizeof are GNU extension
    -Wredundant-decls            # Multiple declarations of the same entity is encountered in the same scope
    -Wshadow                     # Variable/typedef/struct/class/enum shadows another one having same name
    -Wunreachable-code           # Unreachable code
    -Wunused                     # Unused entity (functions, labels, variables, typedefs, parameters, ...)
    -Wwrite-strings              # Deprecated conversion from string literals to 'char *' (enable by default in C++)
    -fmax-errors=50              # Limit number of errors to 50. Default is 0 => no limit
    -fstack-protector-strong     # Checks for buffer overflows such as stack smashing attacks (extra code is added)
    -Wstack-protector            # Warn if option '-fstack-protector-strong' complained about codes vulnerable to stack smashing

    -Wpointer-arith
    -Wshadow
    -Wwrite-strings
    -Wcast-align
    -Wredundant-decls
    -Wdisabled-optimization
    -Wfloat-equal
    -Wmultichar
    -Wmissing-noreturn
    -Woverloaded-virtual
    -Wsign-promo
    -funit-at-a-time
    -Weffc++
    -Wall
    -Wpointer-arith
    -Wshadow
    -Wwrite-strings
    -Wcast-align
    -Wredundant-decls
    -Wdisabled-optimization
    -Wfloat-equal
    -Wmultichar
    -Wmissing-noreturn
    -Woverloaded-virtual
    -Wsign-promo
    -funit-at-a-time
    -Wstrict-null-sentinel
    -Wswitch-enum
    -Wpadded
    -Wfloat-conversion
    -Wunused-macros
    -Wshadow
    -Wmissing-prototypes
)

# Temporary disable some warnings because too much warnings :-(
add_compile_options(
    -Wno-sign-conversion    # 1125 warnings (GCC-6)
    -Wno-padded             #  650 warnings (GCC-6)
    -Wno-unused-parameter   #  577 warnings (GCC-6)
    -Wno-pedantic           #  326 warnings (GCC-6)
    -Wno-cast-qual          #  211 warnings (GCC-6)
    -Wno-conversion         #  123 warnings (GCC-6)
    -Wno-switch-enum        #  111 warnings (GCC-6)

    -Wno-old-style-cast     # 1679 warnings (Clang-3.9)
    -Wno-extra-semi         #  490 warnings (Clang-3.9)
    -Wno-weak-vtables       #  325 warnings (Clang-3.9)
    -Wno-packed             #  304 warnings (Clang-3.9)
    -Wno-documentation      #  187 warnings (Clang-3.9)
    -Wno-reserved-id-macro  #  138 warnings (Clang-3.9)
    -Wno-deprecated         #  123 warnings (Clang-3.9)
)
