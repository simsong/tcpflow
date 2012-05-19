/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Log: tcpflow.h,v $
 * Revision 1.10  2001/08/08 19:39:40  jelson
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
 * Revision 1.9  2000/12/08 07:32:39  jelson
 * Took out the (broken) support for fgetpos/fsetpos.  Now we always simply
 * use fseek and ftell.
 *
 * Revision 1.8  1999/04/21 01:40:16  jelson
 * DLT_NULL fixes, u_char fixes, additions to configure.in, man page update
 *
 * Revision 1.7  1999/04/13 01:38:14  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#ifndef __TCPFLOW_H__
#define __TCPFLOW_H__

#include "config.h"
#include "sysdep.h"
#include "xml.h"

#ifndef __SYSDEP_H__
#error something is messed up
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
extern int debug_level;
#endif

#define DEBUG(message_level) if (debug_level >= message_level) debug_real
#define IS_SET(vector, flag) ((vector) & (flag))
#define SET_BIT(vector, flag) ((vector) |= (flag))


/************************* Function prototypes ****************************/

/* datalink.cpp - callback for libpcap */
pcap_handler find_handler(int datalink_type, const char *device); // callback for pcap

/* flow.cpp - handles the flow database */
void flow_close_all();

/* main.cpp - CLI */
extern const char *progname;
extern int console_only;
extern int suppress_header;
extern int strip_nonprint;
extern int use_color;
extern u_int min_skip;
extern bool opt_no_purge;

#ifdef HAVE_PTHREAD
#include <semaphore.h>
extern sem_t *semlock;
#endif

/* util.c - utility functions */
void init_debug(char *argv[]);
void (*portable_signal(int signo, void (*func)(int)))(int);
void debug_real(const char *fmt, ...)
#ifdef __GNUC__
                __attribute__ ((format (printf, 1, 2)))
#endif
;
void die(const char *fmt, ...)
#ifdef __GNUC__
                __attribute__ ((format (printf, 1, 2)))
#endif
;

#endif /* __TCPFLOW_H__ */
