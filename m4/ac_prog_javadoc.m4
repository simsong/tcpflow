dnl @synopsis AC_PROG_JAVADOC
dnl
dnl AC_PROG_JAVADOC tests for an existing javadoc generator. It uses
dnl the environment variable JAVADOC then tests in sequence various
dnl common javadoc generator.
dnl
dnl If you want to force a specific compiler:
dnl
dnl - at the configure.in level, set JAVADOC=yourgenerator before
dnl calling AC_PROG_JAVADOC
dnl
dnl - at the configure level, setenv JAVADOC
dnl
dnl You can use the JAVADOC variable in your Makefile.in, with
dnl @JAVADOC@.
dnl
dnl Note: This macro depends on the autoconf M4 macros for Java
dnl programs. It is VERY IMPORTANT that you download that whole set,
dnl some macros depend on other. Unfortunately, the autoconf archive
dnl does not support the concept of set of macros, so I had to break it
dnl for submission.
dnl
dnl The general documentation of those macros, as well as the sample
dnl configure.in, is included in the AC_PROG_JAVA macro.
dnl
dnl @category Java
dnl @author Egon Willighagen <e.willighagen@science.ru.nl>
dnl @version 2000-07-19
dnl @license AllPermissive

AC_DEFUN([AC_PROG_JAVADOC],[
AC_REQUIRE([AC_EXEEXT])dnl
if test "x$JAVAPREFIX" = x; then
        test "x$JAVADOC" = x && AC_CHECK_PROGS(JAVADOC, javadoc$EXEEXT)
else
        test "x$JAVADOC" = x && AC_CHECK_PROGS(JAVADOC, javadoc, $JAVAPREFIX)
fi
test "x$JAVADOC" = x && AC_MSG_ERROR([no acceptable javadoc generator found in \$PATH])
AC_PROVIDE([$0])dnl
])
