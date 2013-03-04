#                                               -*- Autoconf -*- 
# Process this file with autoconf to produce a configure script. 
# Order is largely irrevellant, although it must start with AC_INIT and end with AC_OUTPUT 
# See http://autotoolset.sourceforge.net/tutorial.html 
# and http://www.openismus.com/documents/linux/automake/automake.shtml 

AC_INIT(TCPFLOW, 1.4.0_a2, bugs@afflib.org)
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile doc/Makefile])
AC_CONFIG_FILES([doc/tcpflow.1])
AC_CONFIG_FILES([tcpflow.spec])
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

# Endian check is required for MD5 implementation
AC_C_BIGENDIAN

AC_CONFIG_MACRO_DIR([m4])
AC_DEFINE([tcpflow],1,[We are compiling tcpflow])

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
     LIBS="-lpsapi -lws2_32 -lgdi32 $LIBS"  
     CPPFLAGS="-DUNICODE -D_UNICODE -D__MSVCRT_VERSION__=0x0601 -DWINVER=0x0500 -D_WIN32_WINNT=0x0500 -DHAVE_STRUCT_TIMESPEC $CPPFLAGS"
     CFLAGS="$CFLAGS --static"
     CXXFLAGS="$CXXFLAGS -Wno-format "  # compiler mingw-4.3.0 is broken on I64u formats
     CFLAGS="$CFLAGS --static -static-libgcc -static-libstdc++"
     CXXFLAGS="$CXXFLAGS --static -static-libgcc -static-libstdc++"
     mingw="yes"
     ;;		 		     
esac

if test x"${mingw}" == "xno" ; then
  # Bring additional directories where things might be found into our
  # search path. I don't know why autoconf doesn't do this by default
  for spfx in /usr/local /opt/local /sw /usr/local/ssl /usr/boost/include ; do
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


# C++
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
    -Woverloaded-virtual -Wsign-promo \
    -funit-at-a-time"

if test x$CXX != "xclang++" ; then
  # -Wstrict-null-sentinel is not supported under clang
  WARNINGS_TO_TEST="$WARNINGS_TO_TEST -Wstrict-null-sentinel"
fi

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

#
# ZLIB is required for decompressing
#  Note you cannot put comments in the AC_MSG_ERROR for some reason
AC_CHECK_LIB([z],[uncompress],, AC_MSG_WARN([zlib libraries not installed; try installing zlib-dev zlib-devel zlib1g-dev or libz-dev]))
AC_CHECK_HEADERS([zlib.h])

################################################################
## regex support
## there are several options
## tre is better than regex
AC_CHECK_HEADER([lightgrep/api.h])
AC_CHECK_LIB([lightgrep], [lg_create_pattern])
AC_CHECK_HEADERS([regex.h tre/tre.h])
AC_CHECK_LIB([regex],[regcomp])
AC_CHECK_LIB([tre],[tre_regcomp])
AC_CHECK_FUNCS([regcomp tre_regcomp tre_version])


################################################################
# Bulk_extractor plugin support
AC_CHECK_HEADERS([sys/cdefs.h sys/resource.h pwd.h sys/utsname.h tsk3/libtsk3.h unistd.h sys/stat.h])
AC_CHECK_FUNCS([isxdigit ishexnumber])

################################################################
# DFXML support
AC_CHECK_HEADERS([sys/cdefs.h sys/resource.h pwd.h sys/utsname.h regex.h])
AC_CHECK_FUNCS([localtime_r getuid gethostname getwpuid getrusage mkstemp vasprintf regcomp])

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
  #AC_DEFINE([HAVE_STRUCT_TIMESPEC],1,[Required for mingw])
  #CFLAGS="$CFLAGS -mthreads "
  #CPPFLAGS="-DPTW32_STATIC_LIB $CPPFLAGS"
  #CXXFLAGS="$CXXFLAGS -mthreads "
  #AC_DEFINE(HAVE_PTHREAD,1,[Defined to POSIX threads for mingw])
  AC_MSG_NOTICE([pthreads now disabled under mingw])
else
  m4_include([m4/ax_pthread.m4])
  AX_PTHREAD([
    echo Using settings from [AX_PTHREAD]
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
# Boost
AC_CHECK_HEADERS([boost/version.hpp],,
  AC_MSG_WARN([tcpflow now requires boost interval_map and interval_set.])
  if test x"$mingw" = x"yes" ; then 
    AC_MSG_ERROR([Please install mingw32-boost and mingw64-boost])
  else
    AC_MSG_ERROR([Please install boost-devel or libboost-dev.])
  fi
)

# Now make sure we have the correct boost version
AC_LANG_PUSH(C++)
  have_interval=yes
  AC_CHECK_HEADERS([boost/icl/interval.hpp boost/icl/interval_map.hpp boost/icl/interval_set.hpp],,have_interval=no)
  if test "${have_interval}" != yes ; then
    AC_MSG_ERROR([
tcpflow requires a version of Boost that has Boost interval_map and interval_set.
Your version is too old! Please install a current version of Boost from http://www.boost.org/users/download/.
])
  fi
AC_LANG_POP()    

################################################################
# drawing support via cairo
#

AC_CHECK_HEADERS([cairo/cairo.h cairo/cairo-pdf.h])
AC_CHECK_HEADERS([cairo.h cairo-pdf.h])
AC_CHECK_LIB([cairo],[cairo_create], , [
  AC_MSG_WARN([
*** cairo libraries not detected.
*** Please install cairo-devel to get 1-page PDF summary generation.
])
  Fmissing_library="cairo-devel $missing_library"
  Umissing_library="libcairo2-dev $missing_library"
])

################################################################
# pcap support. A bit more involved than normal due to the error message
#
pcap=test
AC_ARG_ENABLE([pcap],[  --enable-pcap=false to disable libpcap even if present])
  if test "${enableval}" = false ; then
    pcap=false
  fi

if test $pcap = test ; then
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
  ])
  Fmissing_library="$Fmissing_library libpcap-dev "
  Umissing_library="$Umissing_library libpcap-dev "
])
fi


################################################################
# Specify our other headers

AC_HEADER_STDC
AC_CHECK_HEADERS([\
	arpa/inet.h \
	ctype.h \
	fcntl.h \
	inttypes.h \
	linux/if_ether.h \
	net/ethernet.h \
	netinet/in.h \
	netinet/in_systm.h \
	netinet/tcp.h \
	pcap.h \
	pcap/pcap.h \
	regex.h \
	semaphore.h \
	signal.h \
	string.h \
	strings.h \
	stdio.h \
	stdlib.h \
	string.h \
	syslog.h \ 
	sys/cdefs.h \
	sys/mman.h \
	sys/resource.h \
	sys/socket.h \
	sys/types.h \
	sys/bitypes.h \
	unistd.h \
	])

AC_CHECK_FUNCS([getdtablesize])

#
# These all require additional headers. See:
# http://www.gnu.org/software/autoconf/manual/autoconf-2.67/html_node/Present-But-Cannot-Be-Compiled.html
#
AC_CHECK_HEADERS([net/if_var.h], [], [],
[[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
]])



AC_CHECK_HEADERS([net/if.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
]])
 
AC_CHECK_HEADERS([netinet/ip_var.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])
 
AC_CHECK_HEADERS([netinet/ip.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])
 
AC_CHECK_HEADERS([netinet/ip_ether.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])
 


AC_CHECK_HEADERS([netinet/tcpip.h], [], [],
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
]])
 
AC_CHECK_FUNCS([inet_ntop sigaction sigset strnstr setuid setgid mmap futimes futimens ])
AC_CHECK_TYPES([socklen_t], [], [], 
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
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

AC_CHECK_TYPES([sa_family_t], [], [], 
[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
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

### AC_CHECK_TYPES([tcp_seq], [], [], 
### [[
### /* from sysdep.h */
### #include <stdio.h>
### #include <stdlib.h>
### 
### #ifdef HAVE_UNISTD_H
### # include <unistd.h>
### #endif
### 
### #ifndef __FAVOR_BSD
### #define __FAVOR_BSD
### #endif
### 
### #ifndef __USE_BSD
### #define __USE_BSD
### #endif
### 
### #ifdef HAVE_ARPA_INET_H
### #include <arpa/inet.h>
### #endif
### 
### #ifdef HAVE_SYS_SOCKET_H
### #include <sys/socket.h>
### #endif
### 
### #ifdef HAVE_NETINET_TCP_H
### #include <netinet/tcp.h>
### #endif
### ]]
### )

############## drop optimization flags if requested ################

# Should we disable optimization?
AC_ARG_WITH([opt], AC_HELP_STRING([--without-opt], [Drop all -O C flags]))
# Or maybe just tone it down a bit?
AC_ARG_WITH([o3], AC_HELP_STRING([--without-o3], [Do not force O3 optimization; use default level]))

if test x"${AFF_NOOPT}" != "x" ; then
  AC_MSG_NOTICE([Dropping optimization flags because AFF_NOOPT is set.])
   with_opt="no";
fi

if test "${with_opt}" = "no" ; then
  AC_MSG_NOTICE([Dropping optimization flags])
  CFLAGS=`echo "$CFLAGS" | sed s/-O[[0-9]]//`             # note the double quoting! 
  CXXFLAGS=`echo "$CXXFLAGS" | sed s/-O[[0-9]]//`
else
  # and increase optimizer from -O2 to -O3 if not explicitly forbidden
  if test "${with_o3}" != "no" ; then
      CFLAGS=`echo   -g "$CFLAGS"   | sed s/-O2/-O3/`             # note the double quoting! 
      CXXFLAGS=`echo -g "$CXXFLAGS" | sed s/-O2/-O3/`
  fi
fi

AC_OUTPUT

if test "x${missing_library}" != "x" ; then
  AC_MSG_NOTICE([*** You may wish to install these libraries: $missing_library])
fi

