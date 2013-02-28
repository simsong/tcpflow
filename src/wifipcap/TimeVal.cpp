////////////////////////////////////////////////////////////////////////////////
// Mercury and Colyseus Software Distribution 
// 
// Copyright (C) 2004-2005 Ashwin Bharambe (ashu@cs.cmu.edu)
//               2004-2005 Jeffrey Pang    (jeffpang@cs.cmu.edu)
//                    2004 Mukesh Agrawal  (mukesh@cs.cmu.edu)
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
  TimeVal.cpp

begin           : Oct 16, 2003
version         : $Id: TimeVal.cpp,v 1.1.1.1 2006/12/14 01:22:11 jpang Exp $
copyright       : (C) 2003      Jeff Pang        ( jeffpang@cs.cmu.edu )
(C) 2003      Justin Weisz     (  jweisz@cs.cmu.edu  )

 ***************************************************************************/

#include <cstdlib>
#include <cstdio>
#include "TimeVal.h"

using namespace std;

TimeVal TIME_NONE = {0,0};

bool operator<(struct timeval a, struct timeval b) {
    return a.tv_sec < b.tv_sec ||
	a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec;
}

bool operator>(struct timeval a, struct timeval b) {
    return a.tv_sec > b.tv_sec ||
	a.tv_sec == b.tv_sec && a.tv_usec > b.tv_usec;
}

bool operator==(struct timeval a, struct timeval b) {
    return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec;
}

bool operator<=(struct timeval a, struct timeval b) {
    return a < b || a == b;
}

bool operator>=(struct timeval a, struct timeval b) {
    return a > b || a == b;
}

bool operator!=(struct timeval a, struct timeval b) {
    return !(a == b);
}

struct timeval operator+(struct timeval a, double add_msec) {
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

sint64 operator-(struct timeval a, struct timeval b) {
    return ((sint64)a.tv_sec - (sint64)b.tv_sec)*USEC_IN_SEC + 
	((sint64)a.tv_usec - (sint64)b.tv_usec);
}

float timeval_to_float (struct timeval a)
{
    return (float) a.tv_sec + ((float) a.tv_usec / USEC_IN_SEC);
}

ostream& operator<<(ostream& os, const TimeVal& t) 
{
    return os << &t;
}

ostream& operator<<(ostream& os, const TimeVal* t)
{
    char buf[64];
    sprintf(buf, "%d.%06d", t->tv_sec, t->tv_usec);
    os << buf;
    return os;
}

// vim: set sw=4 sts=4 ts=8 noet: 
// Local Variables:
// Mode: c++
// c-basic-offset: 4
// tab-width: 8
// indent-tabs-mode: t
// End:
