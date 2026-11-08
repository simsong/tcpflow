# Configure instrumentation for tcpflow and its regression programs.
# Every sanitizer is opt-in and accepts only yes/no values.
# Address and thread instrumentation require separate build directories.
# Both C and C++ sources and executable links receive the selected runtime.
# Configure verifies compiler/runtime link support before testing libraries.
AC_ARG_ENABLE([address-sanitizer], AS_HELP_STRING([--enable-address-sanitizer], [Enable AddressSanitizer]), [], [enable_address_sanitizer=no])
AC_ARG_ENABLE([thread-sanitizer], AS_HELP_STRING([--enable-thread-sanitizer], [Enable ThreadSanitizer]), [], [enable_thread_sanitizer=no])
AC_ARG_ENABLE([undefined-sanitizer], AS_HELP_STRING([--enable-undefined-sanitizer], [Enable UndefinedBehaviorSanitizer]), [], [enable_undefined_sanitizer=no])
for sanitizer_value in "$enable_address_sanitizer" "$enable_thread_sanitizer" "$enable_undefined_sanitizer"; do
    AS_CASE([$sanitizer_value], [yes|no], [], [AC_MSG_ERROR([sanitizer options require yes or no])])
done
AS_IF([test "$enable_address_sanitizer" = yes && test "$enable_thread_sanitizer" = yes],
      [AC_MSG_ERROR([AddressSanitizer and ThreadSanitizer require separate builds])])
tcpflow_sanitizers=
AS_IF([test "$enable_address_sanitizer" = yes], [tcpflow_sanitizers="$tcpflow_sanitizers -fsanitize=address -fsanitize-address-use-after-scope"])
AS_IF([test "$enable_thread_sanitizer" = yes], [tcpflow_sanitizers="$tcpflow_sanitizers -fsanitize=thread"])
AS_IF([test "$enable_undefined_sanitizer" = yes], [tcpflow_sanitizers="$tcpflow_sanitizers -fsanitize=undefined -fno-sanitize-recover=undefined"])
AS_IF([test -n "$tcpflow_sanitizers"], [
    CFLAGS="$CFLAGS -g -O1 -fno-omit-frame-pointer $tcpflow_sanitizers"
    CXXFLAGS="$CXXFLAGS -g -O1 -fno-omit-frame-pointer $tcpflow_sanitizers"
    LDFLAGS="$LDFLAGS $tcpflow_sanitizers"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [], [AC_MSG_ERROR([C compiler cannot link the selected sanitizers])])
    AC_LANG_PUSH([C++])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [], [AC_MSG_ERROR([C++ compiler cannot link the selected sanitizers])])
    AC_LANG_POP([C++])
])
