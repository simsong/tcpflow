#
# mix-ins for dfxml
# Support for hash_t as well.
#
# This file is public domain
# Revision History:
# 2012 - Simson Garfinkel - Created for bulk_extractor
#

AC_MSG_NOTICE([Including dfxml_configure.m4 from dfxml])
AC_MSG_NOTICE([Note: checks for afflib/afflib.h and libewf.h should be in the caller, so they can be disabled])
AC_CHECK_HEADERS([err.h expat.h pwd.h sys/cdefs.h sys/mman.h sys/resource.h sys/utsname.h unistd.h winsock2.h ])
AC_CHECK_FUNCS([fork gmtime_r getuid gethostname getpwuid getrusage mkstemp vasprintf ])

AC_LANG_PUSH(C++)
AC_CHECK_HEADERS([exiv2/image.hpp])
AC_LANG_POP()    


# Determine UTC date offset
CPPFLAGS="$CPPFLAGS -DUTC_OFFSET=`TZ=UTC date +%z`"

# Get the GIT commit into the GIT_COMMIT variable
AC_CHECK_PROG([git],[git],[yes],[no])
AM_CONDITIONAL([FOUND_GIT],[test "x$git" = xyes])
AM_COND_IF([FOUND_GIT],
        [GIT_COMMIT=`git describe --dirty --always`
         AC_MSG_NOTICE([git commit $GIT_COMMIT])],
        [AC_MSG_WARN([git not found])])


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
	       AC_DEFINE([DFXML_GNUC_HAS_DIAGNOSTIC_PRAGMA],[1],[GCC supports #pragma GCC diagnostic]),
	       )

################################################################
## on Win32, crypto requires zlib
case $host in
  *mingw32*)
  AC_CHECK_LIB([z], [gzdopen],[LIBS="-lz $LIBS"], [AC_MSG_ERROR([Could not find zlib library])])
esac

################################################################
## OpenSSL Support is now required (for hash_t)
## Note that this now works with both OpenSSL 1.0 and OpenSSL 1.1
## On OpenSSL man page we can read:
## EVP_MD_CTX_create() and EVP_MD_CTX_destroy() were renamed to EVP_MD_CTX_new() and EVP_MD_CTX_free() in OpenSSL 1.1.
## So we need to check for all of them.
AC_CHECK_HEADERS([openssl/aes.h openssl/bio.h openssl/evp.h openssl/hmac.h openssl/md5.h openssl/pem.h openssl/rand.h openssl/rsa.h openssl/sha.h openssl/pem.h openssl/x509.h])

# OpenSSL has been installed under at least two different names...
AC_CHECK_LIB([crypto],[EVP_get_digestbyname])	
AC_CHECK_LIB([ssl],[SSL_library_init])
AC_CHECK_FUNCS([EVP_get_digestbyname],,
	AC_MSG_ERROR([SSL/OpenSSL support required]))
AC_CHECK_FUNCS([EVP_MD_CTX_new EVP_MD_CTX_free])

