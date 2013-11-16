#include "os.h"
#include <stdarg.h>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#define snprintf sprintf_s
#endif
#include "util.h"
#include "ethertype.h"
#include "wifipcap.h"

//std::ostream& operator<<(std::ostream& out, const WifipcapCallbacks::MAC& mac) {
//    const char *fmt = WifipcapCallbacks::MAC::print_fmt == WifipcapCallbacks::MAC::PRINT_FMT_COLON ? 
//	"%02x:%02x:%02x:%02x:%02x:%02x" :
//	"%02x%02x%02x%02x%02x%02x";
//    char buf[24];
//    sprintf(buf, fmt, 
//	    (int)((mac.val>>40)&0xff),
//	    (int)((mac.val>>32)&0xff),
//	    (int)((mac.val>>24)&0xff),
//	    (int)((mac.val>>16)&0xff),
//	    (int)((mac.val>>8)&0xff),
//	    (int)((mac.val)&0xff)
//	    );
//    out << buf;
//    return out;
//}
//

//std::ostream& operator<<(std::ostream& out, const struct in_addr& ip) {
//    out << inet_ntoa(ip);
//    return out;
//}

char *va(const char *format, ...)
{
    va_list		argptr;
    static int index = 0;
    static char	buf[8][512];
    
    char *b = *(buf + index);

    va_start (argptr, format);
    vsprintf (b, format,argptr);
    va_end (argptr);

    index = (index + 1) % 8;

    return b;	
}

#if 0
const struct tok ethertype_values[] = { 
    { ETHERTYPE_IP,		"IPv4" },
    { ETHERTYPE_MPLS,		"MPLS unicast" },
    { ETHERTYPE_MPLS_MULTI,	"MPLS multicast" },
    { ETHERTYPE_IPV6,		"IPv6" },
    { ETHERTYPE_8021Q,		"802.1Q" },
    { ETHERTYPE_VMAN,		"VMAN" },
    { ETHERTYPE_PUP,            "PUP" },
    { ETHERTYPE_ARP,            "ARP"},
    { ETHERTYPE_REVARP,         "Reverse ARP"},
    { ETHERTYPE_NS,             "NS" },
    { ETHERTYPE_SPRITE,         "Sprite" },
    { ETHERTYPE_TRAIL,          "Trail" },
    { ETHERTYPE_MOPDL,          "MOP DL" },
    { ETHERTYPE_MOPRC,          "MOP RC" },
    { ETHERTYPE_DN,             "DN" },
    { ETHERTYPE_LAT,            "LAT" },
    { ETHERTYPE_SCA,            "SCA" },
    { ETHERTYPE_LANBRIDGE,      "Lanbridge" },
    { ETHERTYPE_DECDNS,         "DEC DNS" },
    { ETHERTYPE_DECDTS,         "DEC DTS" },
    { ETHERTYPE_VEXP,           "VEXP" },
    { ETHERTYPE_VPROD,          "VPROD" },
    { ETHERTYPE_ATALK,          "Appletalk" },
    { ETHERTYPE_AARP,           "Appletalk ARP" },
    { ETHERTYPE_IPX,            "IPX" },
    { ETHERTYPE_PPP,            "PPP" },
    { ETHERTYPE_SLOW,           "Slow Protocols" },
    { ETHERTYPE_PPPOED,         "PPPoE D" },
    { ETHERTYPE_PPPOES,         "PPPoE S" },
    { ETHERTYPE_EAPOL,          "EAPOL" },
    { ETHERTYPE_JUMBO,          "Jumbo" },
    { ETHERTYPE_LOOPBACK,       "Loopback" },
    { ETHERTYPE_ISO,            "OSI" },
    { ETHERTYPE_GRE_ISO,        "GRE-OSI" },
    { 0, NULL}
};

#endif
/*
 * Convert a token value to a string; use "fmt" if not found.
 */
const char *
tok2strbuf(register const struct tok *lp, register const char *fmt,
	   register int v, char *buf, size_t bufsize)
{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}

/*
 * Convert a token value to a string; use "fmt" if not found.
 */
const char *
tok2str(register const struct tok *lp, register const char *fmt,
	register int v)
{
	static char buf[4][128];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}
