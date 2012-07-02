#                                               -*- Autoconf -*- 
# Process this file with autoconf to produce a configure script. 
# Order is largely irrevellant, although it must start with AC_INIT and end with AC_OUTPUT 
# See http://autotoolset.sourceforge.net/tutorial.html 
# and http://www.openismus.com/documents/linux/automake/automake.shtml 

AC_INIT(TCPFLOW, 1.2.7, bugs@afflib.org)
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile doc/Makefile])
AC_CONFIG_FILES([doc/tcpflow.1])
AC_CONFIG_FILES([tcpflow.spec])
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

# Programs we will be using
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL



################################################################
## See if we are running on mingw
# http://osdir.com/ml/gnu.mingw.devel/2003-09/msg00040.html
# Note: Windows 95 WINVER=0x400
# Windows 98 WINVER=0x400  _WIN32_WINDOWS=0x0410
# Windows Me WINVER=0x400  _WIN32_WINDOWS=0x0490
# Windows NT 4.0 WINVER=0x0400  _WIN32_WINNT=0x0400
# Windows NT 4.0 SP3 WINVER=0x0400 _WIN32_WINNT=0x0403
# Windows 2000 WINVER=0x500 _WIN32_WINNT=0x0500
# Windows XP WINVER=0x501 _WIN32_WINNT=0x0501
# Windows Server 2003 WINVER=0x502 _WIN32_WINNT=0x0502
#
# mingw32 includes  i686-w64-mingw32 and  x86_64-w64-mingw32

mingw="no"
case $host in
  *-*-*linux*-*) 
     AC_DEFINE([__LINUX__],1,[Linux operating system functions])
     ;;

  *-*-mingw32*)   
     LIBS="-lws2_32 -lgdi32 $LIBS"  # previously had -liberty 
     CPPFLAGS="-DUNICODE -D_UNICODE -D__MSVCRT_VERSION__=0x0601 -DWINVER=0x0500 -D_WIN32_WINNT=0x0500 -DHAVE_STRUCT_TIMESPEC $CPPFLAGS"
     CXXFLAGS="$CXXFLAGS -Wno-format "  # compiler mingw-4.3.0 is broken on I64u formats
     CFLAGS="$CFLAGS --static"
     CXXFLAGS="$CXXFLAGS --static"
     LDFLAGS="$LDFLAGS -shared-libgcc" # allows exiv2 to throw an exception that's caught elsewhere
     mingw="yes"
     ;;		 		     
esac

if test x"${mingw}" == "xno" ; then
  # Bring additional directories where things might be found into our
  # search path. I don't know why autoconf doesn't do this by default
  for spfx in /usr/local /opt/local /sw /usr/local/ssl; do
    AC_MSG_NOTICE([checking ${spfx}/include])
    if test -d ${spfx}/include; then
        CPPFLAGS="-I${spfx}/include $CPPFLAGS"
        LDFLAGS="-L${spfx}/lib $LDFLAGS"
        AC_MSG_NOTICE([ *** ADDING ${spfx}/include to CPPFLAGS *** ])
        AC_MSG_NOTICE([ *** ADDING ${spfx}/lib to LDFLAGS *** ])
    fi
  done
  AC_MSG_NOTICE([ CPPFLAGS = ${CPPFLAGS} ])        
  AC_MSG_NOTICE([ LDFLAGS = ${LDFLAGS} ])        
fi

if test -r /bin/uname.exe ; then
  if test `uname -o` == "Msys" ; then
    AC_MSG_NOTICE([Compiling with Msys. Setting flags appropriately.])
    LIBS="$LIBS -lws2_32 -lgdi32"
    LDFLAGS="$LDFLAGS -Wl,--enable-auto-import"
  fi
fi

################################################################
#
# Enable all the compiler debugging we can find
#
# This is originally from PhotoRec, but modified substantially by Simson
# Figure out which flags we can use with the compiler. 
#
# These I don't like:
# -Wdeclaration-after-statement -Wconversion
# doesn't work: -Wunreachable-code 
# causes configure to crash on gcc-4.2.1: -Wsign-compare-Winline 
# causes warnings with unistd.h:  -Wnested-externs 
# Just causes too much annoyance: -Wmissing-format-attribute 

# Check GCC
WARNINGS_TO_TEST="-MD -D_FORTIFY_SOURCE=2 -Wpointer-arith -Wmissing-declarations -Wmissing-prototypes \
    -Wshadow -Wwrite-strings -Wcast-align -Waggregate-return \
    -Wbad-function-cast -Wcast-qual -Wundef -Wredundant-decls -Wdisabled-optimization \
    -Wfloat-equal -Wmultichar -Wc++-compat -Wmissing-noreturn "

if test $mingw = "no" ; then
  # add the warnings we do not want to do on mingw
  WARNINGS_TO_TEST="$WARNINGS_TO_TEST -Wall -Wstrict-prototypes"
fi

echo "Warnings to test: $WARNINGS_TO_TEST"

for option in $WARNINGS_TO_TEST
do
  SAVE_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $option"
  AC_MSG_CHECKING([whether gcc understands $option])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
      [has_option=yes],
      [has_option=no; CFLAGS="$SAVE_CFLAGS"])
  AC_MSG_RESULT($has_option)
  unset has_option
  unset SAVE_CFLAGS
  if test $option = "-Wmissing-format-attribute" ; then
    AC_DEFINE(HAVE_MISSING_FORMAT_ATTRIBUTE_WARNING,1,
		[Indicates that we have the -Wmissing-format-attribute G++ warning])
  fi
done
unset option


# Check G++
# We don't use these warnings:
# -Waggregate-return -- aggregate returns are GOOD; they simplify code design
# We can use these warnings after ZLIB gets upgraded:
# -Wundef  --- causes problems with zlib
# -Wcast-qual 
# -Wmissing-format-attribute  --- Just too annoying
AC_LANG_PUSH(C++)
WARNINGS_TO_TEST="-Wall -MD -D_FORTIFY_SOURCE=2 -Wpointer-arith \
    -Wshadow -Wwrite-strings -Wcast-align  \
    -Wredundant-decls -Wdisabled-optimization \
    -Wfloat-equal -Wmultichar -Wmissing-noreturn \
    -Wstrict-null-sentinel -Woverloaded-virtual -Wsign-promo \
    -funit-at-a-time"

if test $mingw = "no" ; then
  # add the warnings we don't want to do on mingw
  WARNINGS_TO_TEST="$WARNINGS_TO_TEST  -Weffc++"
fi

for option in $WARNINGS_TO_TEST
do
  SAVE_CXXFLAGS="$CXXFLAGS"
  CXXFLAGS="$CXXFLAGS $option"
  AC_MSG_CHECKING([whether g++ understands $option])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
      [has_option=yes],
      [has_option=no; CXXFLAGS="$SAVE_CXXFLAGS"])
  AC_MSG_RESULT($has_option)
  unset has_option
  unset SAVE_CXXFLAGS
done
unset option
AC_LANG_POP()    


# ZLIB is required for decompressing
#  Not you cannot put comments in the AC_MSG_ERROR for some reason
AC_CHECK_LIB([z],[uncompress],, AC_MSG_WARN([zlib libraries not installed; try installing zlib-dev zlib-devel zlib1g-dev or libz-dev]))
AC_CHECK_HEADERS([zlib.h])

################################################################
# DFXML support
AC_CHECK_HEADERS([sys/cdefs.h sys/resource.h pwd.h sys/utsname.h])
AC_CHECK_FUNCS([localtime_r getuid gethostname getwpuid getrusage mkstemp vasprintf])

# Determine UTC date offset
CPPFLAGS="$CPPFLAGS -DUTC_OFFSET=`date +%z`"

# Do we have the CPUID instruction?
AC_TRY_COMPILE([#define cpuid(id) __asm__( "cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(id), "b"(0), "c"(0), "d"(0))],
			[unsigned long eax, ebx, ecx, edx;cpuid(0);],
			have_cpuid=yes,
			have_cpuid=no)
if test "$have_cpuid" = yes; then
 AC_DEFINE(HAVE_ASM_CPUID, 1, [define to 1 if __asm__ CPUID is available])
fi

# Does GCC have the diagnostic pragma?
AC_TRY_COMPILE([#pragma GCC diagnostic ignored "-Wredundant-decls"],
    	       [],
	       AC_DEFINE([GNUC_HAS_DIAGNOSTIC_PRAGMA],[1],[GCC supports #pragma GCC diagnostic]),
	       )

################################################################
# PTHREAD support
# With special nods to compiling under mingw

if test  x"$mingw" = x"yes";  then
  AC_DEFINE([HAVE_STRUCT_TIMESPEC],1,[Required for mingw])
  CFLAGS="$CFLAGS -mthreads "
  CPPFLAGS="-DPTW32_STATIC_LIB $CPPFLAGS"
  CXXFLAGS="$CXXFLAGS -mthreads "
  AC_DEFINE(HAVE_PTHREAD,1,[Defined to POSIX threads for mingw])
else
  m4_include([m4/ax_pthread.m4])
  AX_PTHREAD([
    echo Using settings from AX_PTHREAD 
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="  $PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS "
    CPPFLAGS="$PTHREAD_CFLAGS $CPPFLAGS "
    CC="$PTHREAD_CC"
  ])
fi

AC_CHECK_HEADERS([pthread.h])
AC_CHECK_LIB([pthreadGC2],[pthread_create])

################################################################
# pcap support. A bit more involved than normal due to the error message
#
AC_CHECK_LIB(pcap, pcap_lookupdev, , [
	AC_MSG_WARN([
Can't find the pcap library (libpcap.a). 
tcpflow will not live capture or compile rules without pcap!

If you need rules or live capture, you must install the pcap and/or
pcap-dev library.  Please execute this command:

  UBUNTU: sudo apt-get install libpcap-dev
  DEBIAN: sudo apt-get install libpcap-dev
  FEDORA: sudo yum install libpcap-devel
  MINGW:  Sorry!  libpcap is not currently 
          available when cross-compiling.

If your libpcap is installed in a non-standard location, you will need
to use the --with-pcap=directory to specify where your pcap is
located.
  ])])


################################################################
# Specify our other headers

AC_HEADER_STDC
AC_CHECK_HEADERS([\
	arpa/inet.h \
	fcntl.h \
	inttypes.h \
	linux/if_ether.h \
	netinet/if_ether.h \
	netinet/in.h \
	netinet/in_systm.h \
	netinet/ip.h \
	netinet/tcp.h \
	pcap.h \
	pcap/pcap.h \
	regex.h \
	semaphore.h \
	signal.h \
	string.h \
	strings.h \
	sys/cdefs.h \
	sys/mman.h \
	sys/resource.h \
	sys/socket.h \
	sys/types.h \
	sys/bitypes.h \
	unistd.h \
	])

# This is to get net/if.h to compile
AC_CHECK_HEADERS([net/if_var.h net/if.h], [], [],
[[
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
]])
 
AC_CHECK_FUNCS([inet_ntop sigaction sigset strnstr setuid setgid mmap futimes bcopy bzero])
AC_CHECK_TYPES([socklen_t], [], [], 
[[
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
]]
)

AC_CHECK_TYPES([sa_family_t], [], [], 
[[
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
]]
)

AC_CHECK_TYPES([tcp_seq], [], [], 
[[
/* from sysdep.h */
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
]]
)

############## drop optimization flags if requested ################
AC_ARG_WITH(noopt, AC_HELP_STRING([--with-noopt], [Drop -O C flags]))
if test x"${AFF_NOOPT}" != "x" ; then
   with_noopt="yes";
fi

if test "${with_noopt}" = "yes" ; then
  CFLAGS=`echo "$CFLAGS" | sed s/-O[[0-9]]//`             # note the double quoting! 
  CXXFLAGS=`echo "$CXXFLAGS" | sed s/-O[[0-9]]//`
fi

AC_OUTPUT
