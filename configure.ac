#                                               -*- Autoconf -*-
# tcpflow configure.ac
#
# Process this file with autoconf to produce a configure script.
# Order is largely irrevellant, although it must start with AC_INIT and end with AC_OUTPUT
# See http://autotoolset.sourceforge.net/tutorial.html
# and http://www.openismus.com/documents/linux/automake/automake.shtml

AC_PREREQ(2.57)
AC_INIT(TCPFLOW, 1.6.0, simsong@acm.org)
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile doc/Makefile])
AC_CONFIG_FILES([doc/tcpflow.1])
AC_CONFIG_FILES([tcpflow.spec])
AC_CONFIG_HEADER([config.h])

# https://stackoverflow.com/questions/15013672/use-autotools-with-readme-md
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE
AC_PREFIX_PROGRAM(tcpflow) dnl build for same location

# Endian check is required for MD5 implementation
AC_C_BIGENDIAN

# Programs we will be using
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O                  dnl allow per-product flags
AC_PROG_INSTALL

m4_include([m4/slg_searchdirs.m4])
m4_include([m4/slg_gcc_all_warnings.m4])

# Must use C++17 mode. (mandatory)
AC_LANG_PUSH(C++)
AX_CXX_COMPILE_STDCXX([17], [noext], [mandatory])
AC_LANG_POP()


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
     CPPFLAGS="-DUNICODE -D_UNICODE -D__MSVCRT_VERSION__=0x0601 -DWINVER=0x0500 -D_WIN32_WINNT=0x0500 -g $CPPFLAGS"
     CPPFLAGS="$CPPFLAGS --static"
     CFLAGS="$CFLAGS --static -static-libgcc -static-libstdc++"
     CXXFLAGS="$CXXFLAGS -Wno-format "  # compiler mingw-4.3.0 is broken on I64u formats
     CXXFLAGS="$CXXFLAGS --static -static-libgcc -static-libstdc++"
     LDFLAGS="$LDFLAGS --static"
     mingw="yes"
     ;;

   *)
     CXXFLAGS="$CXXFLAGS -Wno-address-of-packed-member"
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
  if test "`uname -o`" == "Msys" ; then
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

add_strict_null_sentinel='yes'
if $CXX -dM -E - < /dev/null | grep -q __clang__ ; then
   AC_MSG_RESULT([Using clang])
   add_strict_null_sentinel='no'
fi

if uname -a | grep -q Darwin; then
   add_strict_null_sentinel='no'
fi

if [ $add_strict_null_sentinel = 'yes' ]; then
   WARNINGS_TO_TEST="$WARNINGS_TO_TEST -Wstrict-null-sentinel"
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

################################################################
##


#
# ZLIB is required for decompressing
#  Note you cannot put comments in the AC_MSG_ERROR for some reason
AC_CHECK_LIB([z],[uncompress],,
  AC_MSG_ERROR([zlib libraries not installed; try installing zlib-dev zlib-devel zlib1g-dev or libz-dev]))
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
## OpenSSL Support (required for hash_t )
AC_CHECK_HEADERS([openssl/aes.h openssl/bio.h openssl/evp.h openssl/hmac.h openssl/md5.h openssl/pem.h openssl/rand.h openssl/rsa.h openssl/sha.h openssl/pem.h openssl/x509.h])
AC_CHECK_LIB([dl],[dlopen])                   dnl apparently OpenSSL now needs -ldl on some Linux
AC_CHECK_LIB([crypto],[EVP_get_digestbyname])	# if crypto is available, get it
AC_CHECK_LIB([md],[MD5])                        # if libmd is available, get it

# Need either SSL_library_init or OPENSSL_init_ssl, depending on openssl version
AC_CHECK_LIB([ssl],[SSL_library_init],,
     AC_CHECK_LIB([ssl],[OPENSSL_init_ssl],,
          AC_MSG_ERROR([OpenSSL developer library 'libssl-dev' or 'openssl-devel' not installed])))

AC_CHECK_FUNCS([MD5_Init EVP_get_digestbyname])

################################################################
## Includes

m4_include([src/be13_api/be13_configure.m4])
m4_include([src/be13_api/dfxml/src/dfxml_configure.m4])

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

Try these commands:
  wget http://downloads.sourceforge.net/project/boost/boost/1.53.0/boost_1_53_0.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fboost%2Ffiles%2Fboost%2F1.53.0%2F&ts=1362359340&use_mirror=hivelocity
  tar xfz boost_1_53_0.tar.gz
  cd boost_1_53_0
  sh bootstrap.sh
  ./b2
  sudo ./b2 install
... and then re-run configure!
])
  fi
AC_LANG_POP()

################################################################
# drawing support via cairo
#
cairo=test
AC_ARG_ENABLE([cairo],[  --enable-cairo=false to disable libcairo even if present])
  if test "${enable_cairo}" = false ; then
    cairo=false
  fi

if test $cairo = test ; then
  # Cairo requires these to be explicitly included on mingw (and perhaps others):
  AC_CHECK_LIB([expat],[XML_ParserCreate])
  AC_CHECK_LIB([pixman-1],[pixman_region_init])
  AC_CHECK_LIB([bz2],[BZ2_bzDecompress])
  AC_CHECK_LIB([freetype],[FT_Init_FreeType]) # requires bz2
  AC_CHECK_LIB([fontconfig],[FcBlanksCreate]) # requires freetype expat

  AC_CHECK_HEADERS([cairo/cairo.h cairo/cairo-pdf.h])
  AC_CHECK_HEADERS([cairo.h cairo-pdf.h])
  AC_CHECK_LIB([cairo],[cairo_create], , [
    AC_MSG_WARN([
  *** cairo libraries not detected.
  *** Please install cairo-devel to get 1-page PDF summary generation.
  ])
    Fmissing_library="$Fmissing_library cairo-devel "
    Umissing_library="$Umissing_library libcairo2-dev "
    Mmissing_library="$Mmissing_library cairo-devel "
  ])
fi

################################################################
# pcap support. A bit more involved than normal due to the error message
#
AC_CHECK_HEADERS(pcap.h pcap/pcap.h )
if test x"$mingw" = x"yes" ; then
    AC_MSG_WARN([pcap not supported under mingw])
else
    AC_CHECK_LIB(pcap, pcap_lookupdev, , [
        enable_pcap=no
	AC_MSG_WARN([
Can't find the pcap library (libpcap.a).
tcpflow will not live capture or compile rules without pcap!

If you need rules or live capture, you must install the pcap and/or
pcap-dev library.  Please execute this command:

  UBUNTU: sudo apt-get install libpcap-dev
  DEBIAN: sudo apt-get install libpcap-dev
  FEDORA: sudo dnf install libpcap-devel
  MINGW:  Sorry!  libpcap is not currently
          available when cross-compiling.

If your libpcap is installed in a non-standard location, you will need
to use the --with-pcap=directory to specify where your pcap is
located.])
        Fmissing_library="$Fmissing_library libpcap-dev "
        Umissing_library="$Umissing_library libpcap-dev "
        Mmissing_library="$Mmissing_library libpcap "
    ])
fi
AC_CHECK_FUNCS([pcap_findalldevs])

dnl set with_wifi to 0 if you do not want it
AC_ARG_ENABLE([wifi],
              AS_HELP_STRING([--disable-wifi], [Disable WIFI decoding]),
              [],
	      [
               if test x"no" = x"$mingw"; then
                 AC_DEFINE(USE_WIFI, 1, [Use WIFI decompression])
                 wifi="yes"
               fi
              ])
AM_CONDITIONAL([WIFI_ENABLED], [test "yes" = "$wifi"])


################################################################
#
# LIBCAP_NG
# Check for libcap-ng
AC_MSG_CHECKING(whether to use libcap-ng)
# Specify location for both includes and libraries.
want_libcap_ng=ifavailable
AC_ARG_WITH(cap_ng,
    AS_HELP_STRING([--with-cap-ng],
		   [use libcap-ng @<:@default=yes, if available@:>@]),
[
	if test $withval = no
	then
		want_libcap_ng=no
		AC_MSG_RESULT(no)
	elif test $withval = yes
	then
		want_libcap_ng=yes
		AC_MSG_RESULT(yes)
	fi
],[
	#
	# Use libcap-ng if it's present, otherwise don't.
	#
	want_libcap_ng=ifavailable
	AC_MSG_RESULT([yes, if available])
])
if test "$want_libcap_ng" != "no"; then
        #
        # note: it really is cap-ng.h, and not cap_ng.h
        #
	AC_CHECK_LIB(cap-ng, capng_change_id)
	AC_CHECK_HEADERS(cap-ng.h)
fi



################################################################
# Specify our other headers

AC_HEADER_STDC
AC_CHECK_HEADERS([\
	arpa/inet.h \
	ctype.h \
	fcntl.h \
        grp.h \
	inttypes.h \
	linux/if_ether.h \
	net/ethernet.h \
	netinet/in.h \
	netinet/in_systm.h \
	netinet/tcp.h \
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
	sys/param.h \
	sys/resource.h \
	sys/socket.h \
	sys/types.h \
	sys/bitypes.h \
	sys/wait.h \
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

################################################################
# Plugin scan_python.cpp requires header "Python.h"
# If the header is not present => Disable the source code of the plugin
#
AC_CHECK_HEADERS(python2.7/Python.h)  # ==> #define HAVE_PYTHON2_7_PYTHON_H
AC_CHECK_LIB(python2.7,Py_Initialize,,[
  AC_MSG_WARN([
*** Cannot find python library.
*** Please install python-devel to enable scanner python.
  ])
  Fmissing_library="$Fmissing_library python-devel "      # Validated on Fedora 25
  Umissing_library="$Umissing_library libpython2.7-dev"   # Should be OK: https://packages.ubuntu.com/yakkety/libpython2.7-dev
  Mmissing_library="$Mmissing_library python27"           # Not sure: https://github.com/macports/macports-ports/blob/master/lang/python27/Portfile
])

################################################################
# Plugin scanner_python.cpp requires header "Python.h"
# If the header is not present => Disable the source code of the plugin
#
AC_CHECK_HEADERS(python2.7/Python.h)  # ==> #define HAVE_PYTHON2_7_PYTHON_H
AC_CHECK_LIB(python2.7,Py_Initialize,,[
  AC_MSG_WARN([
*** Cannot find python library.
*** Please install python-devel to enable scanner python.
  ])
  Fmissing_library="$Fmissing_library python-devel "      # Validated on Fedora 25
  Umissing_library="$Umissing_library libpython2.7-dev"   # Should be OK: https://packages.ubuntu.com/yakkety/libpython2.7-dev
  Mmissing_library="$Mmissing_library python27"           # Not sure: https://github.com/macports/macports-ports/blob/master/lang/python27/Portfile
])

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

  AC_MSG_NOTICE([Removing -D_FORTIFY_SOURCE=2])
  CPPFLAGS=`echo $CPPFLAGS | sed s/-D_FORTIFY_SOURCE=2//`
  CXXFLAGS=`echo $CXXFLAGS | sed s/-D_FORTIFY_SOURCE=2//`
  CFLAGS=`echo $CFLAGS | sed s/-D_FORTIFY_SOURCE=2//`
else
  # and increase optimizer from -O2 to -O3 if not explicitly forbidden
  if test "${with_o3}" != "no" ; then
      CFLAGS=`echo   -g "$CFLAGS"   | sed s/-O2/-O3/`             # note the double quoting!
      CXXFLAGS=`echo -g "$CXXFLAGS" | sed s/-O2/-O3/`
  fi
fi

AC_OUTPUT

## Finally, record the values of CFLAGS, CPPFLAGS, and CXXFLAGS for DFXML
echo "#define CPPFLAGS \"$CPPFLAGS\"" >> config.h
echo "#define CFLAGS   \"$CFLAGS\""   >> config.h
echo "#define CXXFLAGS \"$CXXFLAGS\"" >> config.h
echo "#define LIBS     \"$LIBS\""     >> config.h
echo "#define LDFLAGS  \"$LDFLAGS\""  >> config.h
if test x"$GIT_COMMIT" != "x" ; then
  echo "#define GIT_COMMIT  \"$GIT_COMMIT\""  >> config.h
fi

if test "x${Fmissing_library}" != "x" ; then
  AC_MSG_NOTICE([*** You have missing libraries. To install them:])
  AC_MSG_NOTICE([*** Red Hat: sudo yum install $Fmissing_library])
  AC_MSG_NOTICE([*** Fedora:  sudo dnf install $Fmissing_library])
  AC_MSG_NOTICE([*** Ubuntu:  sudo apt-get install $Umissing_library])
  AC_MSG_NOTICE([*** MacOS:   sudo port install $Mmissing_library])
fi
