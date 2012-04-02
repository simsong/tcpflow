/*
 * This file is part of tcpflow.
 * Originally by Jeremy Elson <jelson@circlemud.org>
 * Substantially revised by Simson Garfinkel <simsong@acm.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * Initial Release: 7 April 1999.
 *
 * $Id: sysdep.h,v 1.5 2001/08/08 19:39:40 jelson Exp $
 *
 * $Log: sysdep.h,v $
 * Revision 1.5  2001/08/08 19:39:40  jelson
 * ARGH!  These are changes that made up tcpflow 0.20, which for some reason I
 * did not check into the repository until now.  (Which of couse means
 * I never tagged v0.20.... argh.)
 *
 * Changes include:
 *
 *   -- portable signal handlers now used to do proper termination
 *
 *   -- patch to allow tcpflow to read from tcpdump stored captures
 *
 * Revision 1.4  2000/12/08 07:32:39  jelson
 * Took out the (broken) support for fgetpos/fsetpos.  Now we always simply
 * use fseek and ftell.
 *
 * Revision 1.3  1999/04/21 01:40:14  jelson
 * DLT_NULL fixes, u_char fixes, additions to configure.in, man page update
 *
 * Revision 1.2  1999/04/13 23:17:56  jelson
 * More portability fixes.  All system header files now conditionally
 * included from sysdep.h.
 *
 * Integrated patch from Johnny Tevessen <j.tevessen@gmx.net> for Linux
 * systems still using libc5.
 *
 * Revision 1.1  1999/04/13 01:38:13  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

/*
 * Set up various machine-specific things based on the values determined
 * from configure and conf.h.
 */


/* Standard C headers  *************************************************/

#ifndef __SYSDEP_H__
#define __SYSDEP_H__

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstdarg>
#include <cerrno>

#include <fcntl.h>
#include <assert.h>

/* If we are including inttypes.h, mmake sure __STDC_FORMAT_MACROS is defined */
#ifdef HAVE_INTTYPES_H
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
# include <inttypes.h>
#else
# error Unable to work without inttypes.h!
#endif


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

#include <sys/stat.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_BITYPES_H
# include<sys/bitypes.h>
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

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#ifndef __USE_BSD
#define __USE_BSD
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

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

/* Linux libc5 systems have different names for certain structures.
 * Patch sent by Johnny Tevessen <j.tevessen@gmx.net> */
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

/* Some systems hasn't defined ETHERTYPE_IPV6 */
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif


/****************************************************************
 *** pcap.h (very improtant to this program)
 ***/
#if !defined(HAVE_PCAP_H) && !defined(HAVE_PCAP_PCAP_H)
#error tcpflow requires pcap.h or pcap/pcap.h
#endif


/* pcap.h has redundant definitions */
#ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#  pragma GCC diagnostic ignored "-Wredundant-decls"
#endif

#ifdef HAVE_PCAP_PCAP_H
#  include <pcap/pcap.h>
#else
#  include <pcap.h>
#endif



/****************** Ugly System Dependencies ******************************/

/* We always want to refer to RLIMIT_NOFILE, even if what you actually
 * have is RLIMIT_OFILE */
#ifdef RLIMIT_OFILE
# ifndef RLIMIT_NOFILE
#  define RLIMIT_NOFILE RLIMIT_OFILE
# endif
#endif

/* We always want to refer to OPEN_MAX, even if what you actually have
 * is FOPEN_MAX. */
#ifdef FOPEN_MAX
# ifndef OPEN_MAX
#  define OPEN_MAX FOPEN_MAX
# endif
#endif

/* some systems don't define SEEK_SET... sigh */
#ifndef SEEK_SET
# define SEEK_SET 0
#endif /* SEEK_SET */

#endif /* __SYSDEP_H__ */

