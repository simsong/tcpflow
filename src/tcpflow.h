/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * 
 *
 */

#ifndef TCPFLOW_H
#define TCPFLOW_H


#include "config.h"

/* Older versions of autoconf define PACKAGE and VERSION.
 * Newer versions define PACKAGE_VERSION and PACKAGE_NAME.
 * We now use the new variables; allow the old ones.
 */

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION VERSION
#endif

#ifndef PACKAGE_NAME
#define PACKAGE_NAME PACAKGE
#endif

/****************************************************************
 *** Windows/mingw compatability seciton.
 ***
 *** If we are compiling for Windows, including the Windows-specific
 *** include files first and disable pthread support.
 ***/
#if (defined(WIN32) || defined(__MINGW32__))
#  undef HAVE_PTHREAD_H
#  undef HAVE_SEMAPHORE_H
#  undef HAVE_PTHREAD
#  undef HAVE_INET_NTOP		/* it's not there. Really. */
#  undef HAVE_EXTERN_PROGNAME	// don't work properly on mingw
#  define MKDIR(a,b) mkdir(a)    // MKDIR only takes 1 argument on windows

/* Defines not present in Microsoft Windows stack */

#else
/*** Unix-specific elements for windows compatibility section ***/
#  define MKDIR(a,b) mkdir(a,b) // MKDIR takes 2 arguments on Posix
#endif

/***
 *** end of windows compatibility section
 ****************************************************************/

/* If we are including inttypes.h, mmake sure __STDC_FORMAT_MACROS is defined */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

/* We want the BSD flavor of defines if possible */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <cstdio>         /* required per C++ standard - use the C++ versions*/
#include <cstdlib>
#include <cctype>
#include <cstdarg>
#include <cerrno>
#include <iostream>
#include <iomanip>

#include <fcntl.h>
#include <assert.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif


// These are the required include files; they better be present
#include <inttypes.h>			
#include <sys/stat.h>

#ifdef HAVE_SYS_CDEFS_H
# include <sys/cdefs.h>
#endif


#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif


#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NE_IF_VAR_H
#include <net/if_var.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif

/* We have given up on keeping track of this all and are just including our own definitions. */


//#ifdef HAVE_NETINET_IN_SYSTM_H
//# include <netinet/in_systm.h>
//#endif

//#ifdef HAVE_NETINET_IP6_H
//#include <netinet/ip6.h>		
//#endif

//#ifdef HAVE_NETINET_IP_VAR_H
//# include <netinet/ip_var.h>		// FREEBSD
//#endif

//#ifdef HAVE_NETINET_IF_ETHER_H
//# include <netinet/if_ether.h>
//#endif

//#ifdef HAVE_NETINET_TCP_H
//# include <netinet/tcp.h>
//#endif

//#ifdef HAVE_NETINET_TCPIP_H
//# include <netinet/tcpip.h>		// FREEBSD
//#endif

//#ifdef HAVE_ARPA_INET_H
//# include <arpa/inet.h>
//#endif


///*
// * Oracle Enterprise Linux is missing the definition for
// * ETHERTYPE_VLAN
// */
//#ifndef ETHERTYPE_VLAN
//# define ETHERTYPE_VLAN 0x8100
//#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif


/****************** Ugly System Dependencies ******************************/

/* We always want to refer to RLIMIT_NOFILE, even if what you actually
 * have is RLIMIT_OFILE
 */
#if defined(RLIMIT_OFILE) && !defined(RLIMIT_NOFILE)
#  define RLIMIT_NOFILE RLIMIT_OFILE
#endif

/* OPEN_MAX is the maximum number of files to open.
 * Unfortunately, some systems called this FOPEN_MAX...
 */
#if defined(FOPEN_MAX) && !defined(OPEN_MAX)
#  define OPEN_MAX FOPEN_MAX
#endif

/* some systems don't define SEEK_SET... sigh */
#ifndef SEEK_SET
# define SEEK_SET 0
#endif /* SEEK_SET */

/* These may not be defined on some systems */

#ifndef MAX_IPv4_STR_LEN
#define MAX_IPv4_STR_LEN (3*4+3)
#endif

#ifndef MAX_IPv6_STR_LEN 
#define MAX_IPv6_STR_LEN 256
#endif

#ifndef HAVE_SOCKLEN_T
typedef size_t socklen_t;
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(x) 0
#endif

#ifndef IN6_IS_ADDR_V4COMPAT
#define IN6_IS_ADDR_V4COMPAT(x) 0
#endif

#undef s6_addr
#define s6_addr			__u6_addr.__u6_addr8

#undef s6_addr16
#define s6_addr16		__u6_addr.__u6_addr16

#undef s6_addr32
#define s6_addr32		__u6_addr.__u6_addr32

#ifdef __MINGW32__
typedef uint16_t in_port_t;
typedef	unsigned char u_int8_t;
#endif

/**************************** Constants ***********************************/

#define DEFAULT_DEBUG_LEVEL 1
#define MAX_FD_GUESS        64
#define SNAPLEN             65536 /* largest possible MTU we'll see */

/* Reserve FDs for stdin, stdout, stderr, and the packet filter; one for breathing
 * room (we open new files before closing old ones), and one more to
 * be safe.
 */
#define NUM_RESERVED_FDS    6    /* number of FDs to set aside; allows files to be opened as necessary */



#include "be13_api/bulk_extractor_i.h"
  
/***************************** Main Support *************************************/

/* tcpflow.cpp - CLI */
extern const char *progname;
void    terminate(int sig) __attribute__ ((__noreturn__));
#include "inet_ntop.h"

#ifdef HAVE_PTHREAD
#include <semaphore.h>
extern sem_t *semlock;
#endif

#ifndef __MAIN_C__
extern int debug;
#endif

#define DEBUG(message_level) if (debug >= message_level) debug_real

/************************* per-file globals  ****************************/

/* datalink.cpp - callback for libpcap */
extern int32_t datalink_tdelta;                                   // time delta to add to each packet
pcap_handler find_handler(int datalink_type, const char *device); // callback for pcap
typedef struct {
    pcap_handler handler;
    int type;
} dlt_handler_t;

void dl_ieee802_11_radio(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void dl_prism(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

/**
 * shift the time value, in line with what the user requested...
 * previously this returned a structure on the stack, but that
 * created an optimization problem with gcc 4.7.2
 */
inline const timeval &tvshift(struct timeval &tv,const struct timeval &tv_)
{
    tv.tv_sec  = tv_.tv_sec + datalink_tdelta;
    tv.tv_usec = tv_.tv_usec;
    return tv;
}



/* util.cpp - utility functions */
extern int debug;
std::string ssprintf(const char *fmt,...);
std::string comma_number_string(int64_t input);
void mkdirs_for_path(std::string path); // creates any directories necessary for the path
std::string macaddr(const uint8_t *addr);

#define DEBUG_PEDANTIC    0x0001       // check values more rigorously
void init_debug(const char *progname,int include_pid);
void (*portable_signal(int signo, void (*func)(int)))(int);
void debug_real(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void die(const char *fmt, ...) __attribute__ ((__noreturn__))  __attribute__ ((format (printf, 1, 2)));

/* scanners */

extern "C" scanner_t scan_md5;
extern "C" scanner_t scan_http;
extern "C" scanner_t scan_tcpdemux;
extern "C" scanner_t scan_netviz;
extern "C" scanner_t scan_wifiviz;


#ifndef HAVE_TIMEVAL_OUT
#define HAVE_TIMEVAL_OUT
inline std::ostream& operator<<(std::ostream& os, const struct timeval *t)
{
    return os << t->tv_sec << "." << std::setw(6) << std::setfill('0') << t->tv_usec;
    
}
#endif

#endif /* __TCPFLOW_H__ */
