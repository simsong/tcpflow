/**
 * A collection of utility functions that are useful.
 */

// Just for this module
#define _FILE_OFFSET_BITS 64

/* required per C++ standard */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "config.h"
#include "cppmutex.h"
#include "utils.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#ifndef HAVE_ERR
#include <stdarg.h>
void err(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
  fprintf(stderr,": %s\n",strerror(errno));
  exit(eval);
}
#endif

#ifndef HAVE_ERRX
#include <stdarg.h>
void errx(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  fprintf(stderr,"%s\n",strerror(errno));
  va_end(ap);
  exit(eval);
}
#endif

#ifndef HAVE_WARN
#include <stdarg.h>
void	warn(const char *fmt, ...)
{
    va_list args;
    va_start(args,fmt);
    vfprintf(stderr,fmt, args);
    fprintf(stderr,": %s\n",strerror(errno));
}
#endif

#ifndef HAVE_WARNX
#include <stdarg.h>
void warnx(const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
}
#endif

/** Extract a buffer...
 * @param buf - the buffer to extract;
 * @param buflen - the size of the page to extract
 * @param pos0 - the byte position of buf[0]
 */

#ifndef HAVE_LOCALTIME_R
/* locking localtime_r implementation */
cppmutex localtime_mutex;
void localtime_r(time_t *t,struct tm *tm)
{
    cppmutex::lock lock(localtime_mutex);
    *tm = *localtime(t);
}
#endif

#ifndef HAVE_GMTIME_R
/* locking gmtime_r implementation */
cppmutex gmtime_mutex;
void gmtime_r(time_t *t,struct tm *tm)
{
    if(t && tm){
	cppmutex::lock lock(gmtime_mutex);
	struct tm *tmret = gmtime(t);
	if(tmret){
	    *tm = *tmret;
	} else {
	    memset(tm,0,sizeof(*tm));
	}
    }
}
#endif



bool ends_with(const std::string &buf,const std::string &with)
{
    size_t buflen = buf.size();
    size_t withlen = with.size();
    return buflen>withlen && buf.substr(buflen-withlen,withlen)==with;
}

bool ends_with(const std::wstring &buf,const std::wstring &with)
{
    size_t buflen = buf.size();
    size_t withlen = with.size();
    return buflen>withlen && buf.substr(buflen-withlen,withlen)==with;
}


#include <sstream>

/****************************************************************/
/* C++ string splitting code from http://stackoverflow.com/questions/236129/how-to-split-a-string-in-c */
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems)
{
    std::stringstream ss(s);
    std::string item;
    while(std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    return split(s, delim, elems);
}




