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
  TimeVal.h

begin           : Oct 16, 2003
version         : $Id: TimeVal.h,v 1.1.1.1 2006/12/14 01:22:11 jpang Exp $
copyright       : (C) 2003      Jeff Pang        ( jeffpang@cs.cmu.edu )
(C) 2003      Justin Weisz     (  jweisz@cs.cmu.edu  )

 ***************************************************************************/

#ifndef __TIME_VAL_H__
#define __TIME_VAL_H__

#include <iostream>
#ifndef _WIN32
#include <sys/time.h>
#include <time.h>
#else
// Guess, this will include the require timeval structures etc... - Ashwin
#include <WinSock2.h>
#endif

#include "types.h"

typedef struct timeval TimeVal;

#define MSEC_IN_SEC 1000
#define USEC_IN_SEC 1000000
#define USEC_IN_MSEC 1000
bool operator<(struct timeval a, struct timeval b);
bool operator<=(struct timeval a, struct timeval b);
bool operator>(struct timeval a, struct timeval b);
bool operator>=(struct timeval a, struct timeval b);
bool operator==(struct timeval a, struct timeval b);
bool operator!=(struct timeval a, struct timeval b);
struct timeval operator+(struct timeval a, double add_msec);
sint64 operator-(struct timeval a, struct timeval b); /* usec result */
float timeval_to_float (struct timeval a);

extern TimeVal TIME_NONE;

std::ostream& operator<<(std::ostream& os, const TimeVal &t);
std::ostream& operator<<(std::ostream& os, const TimeVal *t);
//////////////////////////////////////////////////////////////////////////////

#endif
// vim: set sw=4 sts=4 ts=8 noet: 
// Local Variables:
// Mode: c++
// c-basic-offset: 4
// tab-width: 8
// indent-tabs-mode: t
// End:
