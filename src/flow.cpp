/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id: flow.c,v 1.6 1999/04/13 01:38:11 jelson Exp $
 *
 * $Log: flow.c,v $
 * Revision 1.6  1999/04/13 01:38:11  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#include "tcpflow.h"
#include <assert.h>
#include <iostream>
#include <sstream>


int32_t flow::NO_VLAN = -1;

std::string flow::filename_template("%A.%a-%B.%b%V%v%C%c");

void flow::print_usage()
{
    std::cerr << "Filename template format:\n";
    std::cerr << "  %A - source IP address\n";
    std::cerr << "  %a - source IP port\n";
    std::cerr << "  %B - dest IP address\n";
    std::cerr << "  %b - dest IP port\n";
    std::cerr << "  %T - Timestamp in ISO8601 format\n";
    std::cerr << "  %t - Unix time_t\n";
    std::cerr << "  %V - '--' if VLAN is present\n";
    std::cerr << "  %v - VLAN number if VLAN is present\n";
    std::cerr << "  %C - 'c' if connection_count >0\n";
    std::cerr << "  %c - connection_count if connection_count >0 \n";
    std::cerr << "  %# - always output connection count\n";
    std::cerr << "  %% - Output a '%'\n";
    std::cerr << "\n";
    std::cerr << "Default filename template is " << filename_template << "\n";
}

#define ETH_ALEN 6

#ifndef HAVE_INET_NTOP
/* Fake this code for Windows */
#define MAX_IPv4_STR_LEN (3*4+3)
#define MAX_IPv6_STR_LEN 256
#define bcopy(src,dst,len) memcpy(dst,src,len)
#define bzero(dst,len) memset(dst,0,len)
typedef size_t socklen_t;
#define IN6_IS_ADDR_V4MAPPED(x) 0
#define IN6_IS_ADDR_V4COMPAT(x) 0
struct in6_addr {
    union {
	uint8_t   __u6_addr8[16];
	uint16_t  __u6_addr16[8];
	uint32_t  __u6_addr32[4];
    } __u6_addr;                    /* 128-bit IP6 address */
};

#include "inet_ntop.c"
#endif


std::string flow::filename()
{
    std::stringstream ss;

    for(unsigned int i=0;i<filename_template.size();i++){
	switch(filename_template.at(i)){
	default:
	    ss << filename_template.at(i);
	    break;
	case '%':
	    if(i==filename_template.size()-1){
		std::cerr << "Invalid filename_template: " << filename_template << " cannot end with a %\n";
		exit(1);
	    }
	    /* put the substitute in ss or buf */
	    char buf[1024];
	    buf[0] = 0;
	    switch(filename_template.at(++i)){
	    case 'A': // source IP address
		switch(family){
		case AF_INET:
		    snprintf(buf,sizeof(buf),"%03d.%03d.%03d.%03d", src.addr[0], src.addr[1], src.addr[2], src.addr[3]);
		    break;
		case AF_INET6:
		    inet_ntop(family, src.addr, buf,sizeof(buf));
		}
		break;
	    case 'a': // source IP port
		snprintf(buf,sizeof(buf),"%05d",sport);
		break;
	    case 'B': // dest IP address
		switch(family){
		case AF_INET:
		    snprintf(buf,sizeof(buf),"%03d.%03d.%03d.%03d", dst.addr[0], dst.addr[1], dst.addr[2], dst.addr[3]);
		    break;
		case AF_INET6:
		    inet_ntop(family, dst.addr, buf,sizeof(buf));
		}
		break;
	    case 'b': // dest IP port
		snprintf(buf,sizeof(buf),"%05d",dport);
		break;
	    case 'T': // Timestamp in ISO8601 format
		strftime(buf,sizeof(buf),"%FT%TZ",gmtime(&tstart.tv_sec));
		break;
	    case 't': // Unix time_t
		ss << tstart.tv_sec;
		break;
	    case 'V': // '--' if VLAN is present
		if(vlan!=NO_VLAN) ss << "--";
		break;
	    case 'v': // VLAN number if VLAN is present
		if(vlan!=NO_VLAN) ss << vlan;
		break;
	    case 'C': // 'c' if connection_count >0
		if(connection_count>0) ss << "c";
		break;
	    case 'c': // connection_count if connection_count >0
		if(connection_count>0) ss << connection_count;
		break;
	    case '#': // always output connection count
		ss << connection_count;
		break;
	    case '%': // Output a '%'
		ss << "%";
		break;
	    default:
		std::cerr << "Invalid filename_template: " << filename_template << "\n";
		std::cerr << "unknown character: " << filename_template.at(i+1) << "\n";
		exit(1);
	    }
	    if(buf[0]) ss << buf;
	}
    }
    return ss.str();
}
