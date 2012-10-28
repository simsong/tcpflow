/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#ifndef __TCPFLOW_H__
#define __TCPFLOW_H__

#include "config.h"

/* If we are running on Windows, including the Windows-specific
 * include files first and disable pthread support.
 */
#ifdef WIN32
#  include <winsock2.h>
#  include <windows.h>
#  include <windowsx.h>
#undef HAVE_PTHREAD_H
#undef HAVE_SEMAPHORE_H
#undef HAVE_PTHREAD
#undef HAVE_INET_NTOP		/* it's not there. Really. */


#  define MKDIR(a,b) mkdir(a)  // MKDIR only takes 1 argument on windows
#else
#  define MKDIR(a,b) mkdir(a,b)		// MKDIR takes 2 arguments on Posix
#endif

#include <cstdio>         /* required per C++ standard - use the C++ versions*/
#include <cstdlib>
#include <cctype>
#include <cstdarg>
#include <cerrno>

#include <fcntl.h>
#include <assert.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

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

#ifdef HAVE_NET_ETHERNET_H
# include <net/ethernet.h>		// for freebsd
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>		
#endif

#ifdef HAVE_NETINET_IP_VAR_H
# include <netinet/ip_var.h>		// FREEBSD
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_NETINET_TCPIP_H
# include <netinet/tcpip.h>		// FREEBSD
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

/* Linux libc5 systems have different names for certain structures.
 * Patch sent by Johnny Tevessen <j.tevessen@gmx.net>
 */
#if !defined(HAVE_NETINET_IF_ETHER_H) && defined(HAVE_LINUX_IF_ETHER_H)
# include <linux/if_ether.h>
# define ether_header ethhdr
# define ether_type h_proto
# define ETHERTYPE_IP ETH_P_IP
#endif

/*
 * Oracle Enterprise Linux is missing the definition for
 * ETHERTYPE_VLAN
 */
#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN 0x8100
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif


/****************************************************************
 *** pcap.h --- If we don't have it, fake it. ---
 ***/
#if defined(HAVE_LIBPCAP)

/* pcap.h has redundant definitions */
#  ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#    pragma GCC diagnostic ignored "-Wredundant-decls"
#  endif

#  ifdef HAVE_PCAP_PCAP_H
#    include <pcap/pcap.h>
#  else
#    include <pcap.h>
#  endif

#  ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#    pragma GCC diagnostic warning "-Wredundant-decls"
#  endif

#else
#  include "pcap_fake.h"
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

#include "xml.h"

/* These may not be defined on some systems */

#ifndef MAX_IPv4_STR_LEN
#define MAX_IPv4_STR_LEN (3*4+3)
#endif

#ifndef MAX_IPv6_STR_LEN 
#define MAX_IPv6_STR_LEN 256
#endif

#ifndef HAVE_BCOPY
#define bcopy(src,dst,len) memcpy(dst,src,len)
#endif

#ifndef HAVE_BZERO
#define bzero(dst,len)     memset(dst,0,len)
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

struct private_in6_addr {		// our own private ipv6 definition
    union {
	uint8_t   __u6_addr8[16];
	uint16_t  __u6_addr16[8];
	uint32_t  __u6_addr32[4];
    } __u6_addr;                    /* 128-bit IP6 address */
};
#undef s6_addr
#define s6_addr			__u6_addr.__u6_addr8

#undef s6_addr16
#define s6_addr16		__u6_addr.__u6_addr16

#undef s6_addr32
#define s6_addr32		__u6_addr.__u6_addr32


#ifdef _WIN32
/* For some reason this doesn't work properly with mingw */
#undef HAVE_EXTERN_PROGNAME
#endif

/**************************** Constants ***********************************/

#define DEFAULT_DEBUG_LEVEL 1
#define MAX_FD_GUESS        64
#define NUM_RESERVED_FDS    5     /* number of FDs to set aside */
#define SNAPLEN             65536 /* largest possible MTU we'll see */

#include <iostream>

#include "tcpdemux.h"
  
/***************************** Macros *************************************/

#ifndef __MAIN_C__
extern int debug;
#endif

#define DEBUG(message_level) if (debug >= message_level) debug_real
#define IS_SET(vector, flag) ((vector) & (flag))
#define SET_BIT(vector, flag) ((vector) |= (flag))


/************************* Function prototypes ****************************/

/* datalink.cpp - callback for libpcap */
pcap_handler find_handler(int datalink_type, const char *device); // callback for pcap

/* flow.cpp - handles the flow database */
void flow_close_all();

/* main.cpp - CLI */
extern const char *progname;

#ifdef HAVE_PTHREAD
#include <semaphore.h>
extern sem_t *semlock;
#endif

/* util.c - utility functions */
void init_debug(char *argv[]);
void (*portable_signal(int signo, void (*func)(int)))(int);
void debug_real(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void die(const char *fmt, ...) __attribute__ ((__noreturn__))  __attribute__ ((format (printf, 1, 2)));


#endif /* __TCPFLOW_H__ */
