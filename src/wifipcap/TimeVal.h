////////////////////////////////////////////////////////////////////////////////
// Mercury and Colyseus Software Distribution 
// 
// Copyright (C) 2004-2005 Ashwin Bharambe (ashu@cs.cmu.edu)
//               2004-2005 Jeffrey Pang    (jeffpang@cs.cmu.edu)
//                    2004 Mukesh Agrawal  (mukesh@cs.cmu.edu)
//                    2013 Simson L. Garfinkel (simsong@acm.org)
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 2, or (at
// your option) any later version.
// 
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA
////////////////////////////////////////////////////////////////////////////////
/* -*- Mode:c++; c-basic-offset:4; tab-width:4; indent-tabs-mode:t -*- */

/**************************************************************************
  TimeVal.h

begin           : Oct 16, 2003
version         : $Id: TimeVal.h,v 1.1.1.1 2006/12/14 01:22:11 jpang Exp $
copyright       : (C) 2003      Jeff Pang        ( jeffpang@cs.cmu.edu )
                  (C) 2003      Justin Weisz     ( jweisz@cs.cmu.edu   )
                  (C) 2013      Simson Garfinkel ( simsong@acm.org )

 ***************************************************************************/

#ifndef __TIME_VAL_H__
#define __TIME_VAL_H__

#include <iostream>
#include <iomanip>

#ifndef _WIN32
#include <sys/time.h>
#include <time.h>
#else
#include <winsock2.h>
#endif

#include "types.h"

typedef struct timeval TimeVal;

#define MSEC_IN_SEC 1000
#define USEC_IN_SEC 1000000
#define USEC_IN_MSEC 1000

inline bool operator<(struct timeval a, struct timeval b) {
    return (a.tv_sec < b.tv_sec) || ((a.tv_sec == b.tv_sec) && (a.tv_usec < b.tv_usec));
}

inline bool operator>(struct timeval a, struct timeval b) {
    return (a.tv_sec > b.tv_sec) || ((a.tv_sec == b.tv_sec) && (a.tv_usec > b.tv_usec));
}

inline bool operator==(struct timeval a, struct timeval b) {
    return (a.tv_sec == b.tv_sec) && (a.tv_usec == b.tv_usec);
}

inline bool operator<=(struct timeval a, struct timeval b) {
    return a < b || a == b;
}

inline bool operator>=(struct timeval a, struct timeval b) {
    return a > b || a == b;
}

inline bool operator!=(struct timeval a, struct timeval b) {
    return !(a == b);
}

inline struct timeval operator+(struct timeval a, double add_msec) {
    struct timeval ret;

    // convert into sec/usec parts
    sint32 sec_part  = (sint32)(add_msec/MSEC_IN_SEC);
    sint32 usec_part = (sint32)((add_msec - sec_part * MSEC_IN_SEC)*USEC_IN_MSEC);

    // do the initial addition
    ret.tv_sec  = a.tv_sec + sec_part;
    ret.tv_usec = a.tv_usec + usec_part;

    // perform a carry if necessary
    if (ret.tv_usec > USEC_IN_SEC) {
	ret.tv_sec++;
	ret.tv_usec = ret.tv_usec % USEC_IN_SEC;
    } else if (ret.tv_usec < 0) {
	ret.tv_sec--;
	ret.tv_usec = USEC_IN_SEC + ret.tv_usec;
    }

    return ret;
}

inline int64_t operator-(struct timeval a, struct timeval b) {
    return ((sint64)a.tv_sec - (sint64)b.tv_sec)*USEC_IN_SEC + 
	((sint64)a.tv_usec - (sint64)b.tv_usec);
}

inline float timeval_to_float (struct timeval a)
{
    return (float) a.tv_sec + ((float) a.tv_usec / USEC_IN_SEC);
}

inline std::ostream& operator<<(std::ostream& os, const TimeVal& t) 
{
    return os << &t;
}

#ifndef HAVE_TIMEVAL_OUT
#define HAVE_TIMEVAL_OUT
inline std::ostream& operator<<(std::ostream& os, const TimeVal* t)
{
    return os << t->tv_sec << "." << std::setw(6) << std::setfill('0') << t->tv_usec;
    
}
#endif

//bool operator<(struct timeval a, struct timeval b);
//bool operator<=(struct timeval a, struct timeval b);
//bool operator>(struct timeval a, struct timeval b);
//bool operator>=(struct timeval a, struct timeval b);
//bool operator==(struct timeval a, struct timeval b);
//bool operator!=(struct timeval a, struct timeval b);
//struct timeval operator+(struct timeval a, double add_msec);
//sint64 operator-(struct timeval a, struct timeval b); /* usec result */
//float timeval_to_float (struct timeval a);

extern TimeVal TIME_NONE;

//std::ostream& operator<<(std::ostream& os, const TimeVal &t);
//std::ostream& operator<<(std::ostream& os, const TimeVal *t);
//////////////////////////////////////////////////////////////////////////////

#endif
