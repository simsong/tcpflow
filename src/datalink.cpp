/**
 * 
 * This file is part of tcpflow. Originally by Jeremy Elson
 * <jelson@circlemud.org>, rewritten by Simson Garfinkel.
 *
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * This file contains datalink handlers which are called by the pcap callback.
 * The purpose of each handler is to make a packet_info() object and then call
 * process_packet_info. The packet_info() object contains both the original
 * MAC-layer (with some of the fields broken out) and the packet data layer.
 */

#include "tcpflow.h"
//#include "be13_api/net_ethernet.h"

/* The DLT_NULL packet header is 4 bytes long. It contains a network
 * order 32 bit integer that specifies the family, e.g. AF_INET.
 * DLT_NULL is used by the localhost interface.
 */
#define	NULL_HDRLEN 4

/* Some systems hasn't defined ETHERTYPE_IPV6 */
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

int32_t datalink_tdelta = 0;


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


#pragma GCC diagnostic ignored "-Wcast-align"
void dl_null(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;
    uint32_t family = *(uint32_t *)p;

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte null frame",
		  caplen, length);
    }

    if (caplen < NULL_HDRLEN) {
	DEBUG(6) ("warning: received incomplete null frame");
	return;
    }

    /* One of the symptoms of a broken DLT_NULL is that this value is
     * not set correctly, so we don't check for it -- instead, just
     * assume everything is IP.  --JE 20 April 1999
     */
#ifndef DLT_NULL_BROKEN
    /* make sure this is AF_INET */
    if (family != AF_INET && family != AF_INET6) {
	DEBUG(6)("warning: received null frame with unknown type (type 0x%x) (AF_INET=%x; AF_INET6=%x)",
		 family,AF_INET,AF_INET6);
	return;
    }
#endif
    struct timeval tv;
    be13::packet_info pi(DLT_NULL,h,p,tvshift(tv,h->ts),p+NULL_HDRLEN,caplen - NULL_HDRLEN);
    process_packet_info(pi);
}
#pragma GCC diagnostic warning "-Wcast-align"

#ifdef DLT_RAW
/* DLT_RAW: just a raw IP packet, no encapsulation or link-layer
 * headers.  Used for PPP connections under some OSs including Linux
 * and IRIX. */
void dl_raw(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    if (h->caplen != h->len) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte raw frame",
		  h->caplen, h->len);
    }
    struct timeval tv;
    be13::packet_info pi(DLT_RAW,h,p,tvshift(tv,h->ts),p, h->caplen);
    process_packet_info(pi);
}
#endif

/* Ethernet datalink handler; used by all 10 and 100 mbit/sec
 * ethernet.  We are given the entire ethernet header so we check to
 * make sure it's marked as being IP.
 */
#pragma GCC diagnostic ignored "-Wcast-align"
void dl_ethernet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;
    struct be13::ether_header *eth_header = (struct be13::ether_header *) p;

    /* Variables to support VLAN */
    const u_short *ether_type = &eth_header->ether_type; /* where the ether type is located */
    const u_char *ether_data = p+sizeof(struct be13::ether_header); /* where the data is located */

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte ether frame",
		  caplen, length);
    }

    /* Handle basic VLAN packets */
    if (ntohs(*ether_type) == ETHERTYPE_VLAN) {
	//vlan = ntohs(*(u_short *)(p+sizeof(struct ether_header)));
	ether_type += 2;			/* skip past VLAN header (note it skips by 2s) */
	ether_data += 4;			/* skip past VLAN header */
	caplen     -= 4;
    }
  
    if (caplen < sizeof(struct be13::ether_header)) {
	DEBUG(6) ("warning: received incomplete ethernet frame");
	return;
    }

    /* Create a packet_info structure with ip data and data length  */
    struct timeval tv;
    be13::packet_info pi(DLT_IEEE802,h,p,tvshift(tv,h->ts),ether_data, caplen - sizeof(struct be13::ether_header));
    switch (ntohs(*ether_type)){
    case ETHERTYPE_IP:
    case ETHERTYPE_IPV6:
        process_packet_info(pi);
        break;

#ifdef ETHERTYPE_ARP
    case ETHERTYPE_ARP:
        /* What should we do for ARP? */
        break;
#endif
#ifdef ETHERTYPE_LOOPBACK
    case ETHERTYPE_LOOPBACK:
        /* What do do for loopback? */
        break;
#endif
#ifdef ETHERTYPE_REVARP
    case ETHERTYPE_REVARP:
        /* What to do for REVARP? */
        break;
#endif
    default:
        /* Unknown Ethernet Frame Type */
        DEBUG(6) ("warning: received ethernet frame with unknown type 0x%x", ntohs(eth_header->ether_type));
	break;
    }
}

#pragma GCC diagnostic warning "-Wcast-align"

/* The DLT_PPP packet header is 4 bytes long.  We just move past it
 * without parsing it.  It is used for PPP on some OSs (DLT_RAW is
 * used by others; see below)
 */
#define	PPP_HDRLEN 4

void dl_ppp(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte PPP frame",
		  caplen, length);
    }

    if (caplen < PPP_HDRLEN) {
	DEBUG(6) ("warning: received incomplete PPP frame");
	return;
    }

    struct timeval tv;
    be13::packet_info pi(DLT_PPP,h,p,tvshift(tv,h->ts),p + PPP_HDRLEN, caplen - PPP_HDRLEN);
    process_packet_info(pi);
}


#ifdef DLT_LINUX_SLL
#define SLL_HDR_LEN       16
void dl_linux_sll(u_char *user, const struct pcap_pkthdr *h, const u_char *p){
    u_int caplen = h->caplen;
    u_int length = h->len;

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte Linux cooked frame",
		  caplen, length);
    }

    if (caplen < SLL_HDR_LEN) {
	DEBUG(6) ("warning: received incomplete Linux cooked frame");
	return;
    }
  
    struct timeval tv;
    be13::packet_info pi(DLT_LINUX_SLL,h,p,tvshift(tv,h->ts),p + SLL_HDR_LEN, caplen - SLL_HDR_LEN);
    process_packet_info(pi);
}
#endif


/* List of callbacks for each data link type */
typedef struct {
    pcap_handler handler;
    int type;
} dlt_handlers;

dlt_handlers handlers[] = {
    { dl_null,	   DLT_NULL },
#ifdef DLT_RAW /* older versions of libpcap do not have DLT_RAW */
    { dl_raw,      DLT_RAW },
#endif
    { dl_ethernet, DLT_EN10MB },
    { dl_ethernet, DLT_IEEE802 },
    { dl_ppp,      DLT_PPP },
#ifdef DLT_LINUX_SLL
    { dl_linux_sll,DLT_LINUX_SLL },
#endif
    { NULL, 0 },
};

pcap_handler find_handler(int datalink_type, const char *device)
{
    int i;

    DEBUG(3) ("looking for handler for datalink type %d for interface %s",
	      datalink_type, device);

    for (i = 0; handlers[i].handler != NULL; i++){
	if (handlers[i].type == datalink_type) return handlers[i].handler;
    }

    die("sorry - unknown datalink type %d on interface %s", datalink_type, device);
    return NULL;    /* NOTREACHED */
}

