/****************************************************************
 *** utils.h
 *** 
 *** To use utils.c/utils.h, be sure this is in your configure.ac file:
      m4_include([be13_api/be13_configure.m4])
 ***
 ****************************************************************/



#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <stdint.h>
#include <sys/time.h>

#if defined(__cplusplus)
#include <string>
#include <vector>
bool ends_with(const std::string &buf,const std::string &with);
bool ends_with(const std::wstring &buf,const std::wstring &with);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
std::vector<std::string> split(const std::string &s, char delim);
#endif



#ifndef __BEGIN_DECLS
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

__BEGIN_DECLS

#ifdef HAVE_ERR_H
#include <err.h>
#else
[[noreturn]] void err(int eval,const char *fmt,...) __attribute__((format(printf, 2, 0)));
[[noreturn]] void errx(int eval,const char *fmt,...) __attribute__((format(printf, 2, 0)));
void warn(const char *fmt, ...) __attribute__((format(printf, 1, 0)));
void warnx(const char *fmt,...) __attribute__((format(printf, 1, 0)));
#endif

#ifndef HAVE_LOCALTIME_R
#ifdef __MINGW32__
#undef localtime_r
#endif
void localtime_r(time_t *t,struct tm *tm);
#endif

#ifndef HAVE_GMTIME_R
#ifdef __MINGW32__
#undef gmtime_r
#endif
void gmtime_r(time_t *t,struct tm *tm);
#endif

int64_t get_filesize(int fd);

#ifndef HAVE_ISHEXNUMBER
int ishexnumber(int c);
inline int ishexnumber(int c)
{
    switch(c){
    case '0':         case '1':         case '2':         case '3':         case '4':
    case '5':         case '6':         case '7':         case '8':         case '9':
    case 'A':         case 'B':         case 'C':         case 'D':         case 'E':
    case 'F':         case 'a':         case 'b':         case 'c':         case 'd':
    case 'e':         case 'f':
	return 1;
    }
    return 0;
}
#endif
__END_DECLS


#endif
