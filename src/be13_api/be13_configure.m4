#
# mix-ins for be13
#

AC_MSG_NOTICE([Including be13_configure.m4 from be13_api])
AC_CHECK_HEADERS([err.h pwd.h sys/cdefs.h sys/mman.h sys/resource.h sys/utsname.h unistd.h sqlite3.h ])
AC_CHECK_FUNCS([gmtime_r ishexnumber isxdigit localtime_r unistd.h mmap err errx warn warnx pread64 pread strptime _lseeki64 utimes ])

AC_CHECK_LIB([sqlite3],[sqlite3_libversion])
AC_CHECK_FUNCS([sqlite3_create_function_v2])

AC_TRY_COMPILE([#pragma GCC diagnostic ignored "-Wredundant-decls"],[int a=3;],
  [AC_DEFINE(HAVE_DIAGNOSTIC_REDUNDANT_DECLS,1,[define 1 if GCC supports -Wredundant-decls])]
)
AC_TRY_COMPILE([#pragma GCC diagnostic ignored "-Wcast-align"],[int a=3;],
  [AC_DEFINE(HAVE_DIAGNOSTIC_CAST_ALIGN,1,[define 1 if GCC supports -Wcast-align])]
)

AC_TRY_LINK([#include <inttypes.h>],
               [uint64_t ul; __sync_add_and_fetch(&ul,0);],
               AC_DEFINE(HAVE___SYNC_ADD_AND_FETCH,1,[define 1 if __sync_add_and_fetch works on 64-bit numbers]))

#
# Figure out which version of unordered_map we are going to use
#
AC_LANG_PUSH(C++)
  AC_MSG_NOTICE([checking for unordered_map])
  AC_MSG_NOTICE([  CXXFLAGS:           $CXXFLAGS])
  AC_CHECK_HEADERS([unordered_map unordered_set],[],[
    AC_CHECK_HEADERS([tr1/unordered_map tr1/unordered_set])])
  AC_MSG_NOTICE([done])
AC_LANG_POP()    

