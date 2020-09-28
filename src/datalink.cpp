/**
 *
 * This file is part of tcpflow. Originally by Jeremy Elson
 * <jelson@circlemud.org>, rewritten by Simson Garfinkel.
 *
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * COPYING for details.
 *
 * This file contains datalink handlers which are called by the pcap callback.
 * The purpose of each handler is to make a packet_info() object and then call
 * process_packet. The packet_info() object contains both the original
 * MAC-layer (with some of the fields broken out) and the packet data layer.
 *
 * For wifi datalink handlers, please see datalink_wifi.cpp
 */

#include <stddef.h>
#include "tcpflow.h"

/* The DLT_NULL packet header is 4 bytes long. It contains a network
 * order 32 bit integer that specifies the family, e.g. AF_INET.
 * DLT_NULL is used by the localhost interface.
 */
#define	NULL_HDRLEN 4

/* Some systems hasn't defined ETHERTYPE_IPV6 */
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#ifndef ETH_P_QINQ1
# define ETH_P_QINQ1	0x9100		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#endif

#ifndef ETH_P_8021AD
# define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/
#endif


int32_t datalink_tdelta = 0;

#pragma GCC diagnostic ignored "-Wcast-align"
void dl_null(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;
    uint32_t family = (uint32_t)*p;

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte null frame",
		  caplen, length);
    }

    if (caplen < NULL_HDRLEN) {
	DEBUG(6) ("warning: received incomplete null frame");
	return;
    }

    /* make sure this is AF_INET */
    if (family != AF_INET && family != AF_INET6) {
	DEBUG(6)("warning: received null frame with unknown type (type 0x%x) (AF_INET=%x; AF_INET6=%x)",
		 family,AF_INET,AF_INET6);
	return;
    }
    struct timeval tv;
    be13::packet_info pi(DLT_NULL,h,p,tvshift(tv,h->ts),p+NULL_HDRLEN,caplen - NULL_HDRLEN);
    be13::plugin::process_packet(pi);
}
#pragma GCC diagnostic warning "-Wcast-align"

static uint64_t counter=0;
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
    counter++;
    be13::plugin::process_packet(pi);
}

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
    u_int ether_type_offset = offsetof(struct be13::ether_header, ether_type);

    /* Variables to support VLAN */
    const u_short *ether_type = NULL;
    const u_char *ether_data = NULL;

    if (caplen < ether_type_offset) {
        DEBUG(0) ("error: the captured packet header bytes are shorter than the ether_type offset");
        return;
    }

    ether_type = &eth_header->ether_type; /* where the ether type is located */
    ether_data = p+sizeof(struct be13::ether_header); /* where the data is located */

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte ether frame",
		  caplen, length);
    }

    /* Handle basic VLAN packets */
    while (ntohs(*ether_type) == ETHERTYPE_VLAN
#ifdef ETH_P_QINQ1
           || ntohs(*ether_type) == ETH_P_QINQ1
#endif
#ifdef ETH_P_8021AD
           || ntohs(*ether_type) == ETH_P_8021AD
#endif
           ) {
	//vlan = ntohs(*(u_short *)(p+sizeof(struct ether_header)));
	ether_type += 2;			/* skip past VLAN header (note it skips by 2s) */
	ether_data += 4;			/* skip past VLAN header */
	caplen     -= 4;
        if (caplen < ether_type_offset) {
            DEBUG(0) ("error: the captured packet header bytes are shorter than the ether_type offset");
            return;
        }
    }

    if (caplen < sizeof(struct be13::ether_header)) {
	DEBUG(6) ("warning: received incomplete ethernet frame");
	return;
    }

    /* Create a packet_info structure with ip data and data length  */
    try {
        struct timeval tv;
        be13::packet_info pi(DLT_IEEE802,h,p,tvshift(tv,h->ts),
                             ether_data, caplen - sizeof(struct be13::ether_header));
        switch (ntohs(*ether_type)){
        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            be13::plugin::process_packet(pi);
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
    } catch( std::logic_error e){
        std::string s(std::string("warning: caught std::logic_error ")
                      + e.what()
                      + std::string(" in packet"));
        DEBUG(6)(s.c_str());
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
    be13::plugin::process_packet(pi);
}


#ifdef DLT_LINUX_SLL
#define SLL_HDR_LEN       16

#define SLL_ADDRLEN 8

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS      0x8847
#endif
#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI    0x8848
#endif

#pragma GCC diagnostic ignored "-Wcast-align"
void dl_linux_sll(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
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

    struct _sll_header {
        u_int16_t   sll_pkttype;    /* packet type */
        u_int16_t   sll_hatype; /* link-layer address type */
        u_int16_t   sll_halen;  /* link-layer address length */
        u_int8_t    sll_addr[SLL_ADDRLEN];  /* link-layer address */
        u_int16_t   sll_protocol;   /* protocol */
    };

    _sll_header *sllp = (_sll_header*)p;
    u_int mpls_sz = 0;
    if (ntohs(sllp->sll_protocol) == ETHERTYPE_MPLS) {
        // unwind MPLS stack
        do {
            if(caplen < SLL_HDR_LEN + mpls_sz + 4){
                DEBUG(6) ("warning: MPLS stack overrun");
                return;
            }
            mpls_sz += 4;
            caplen -= 4;
        } while ((p[SLL_HDR_LEN + mpls_sz - 2] & 1) == 0 );
    }

    struct timeval tv;
    be13::packet_info pi(DLT_LINUX_SLL,h,p,tvshift(tv,h->ts),p + SLL_HDR_LEN + mpls_sz, caplen - SLL_HDR_LEN);
    be13::plugin::process_packet(pi);
}
#endif

#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO    127  /* 802.11 plus radiotap radio header */
#endif

/* List of callbacks for each data link type */
dlt_handler_t handlers[] = {
    { dl_null,	   DLT_NULL },
/* Some systems define DLT_RAW as 12, some as 14, and some as 101.
 * So it is hard-coded here.
 */
    { dl_raw,      12 },
    { dl_raw,      14 },
    { dl_raw,     101 },
    { dl_ethernet, DLT_EN10MB },
    { dl_ethernet, DLT_IEEE802 },
    { dl_ppp,           DLT_PPP },
#ifdef DLT_LINUX_SLL
    { dl_linux_sll,        DLT_LINUX_SLL },
#endif
#if defined(USE_WIFI) && !defined(WIN32)
    { dl_ieee802_11_radio, DLT_IEEE802_11 },
    { dl_ieee802_11_radio, DLT_IEEE802_11_RADIO },
    { dl_prism,            DLT_PRISM_HEADER},
#endif
    { NULL, 0 }
};

pcap_handler find_handler(int datalink_type, const char *device)
{
    int i;

    DEBUG(3) ("looking for handler for datalink type %d for interface %s",
	      datalink_type, device);

    for (i = 0; handlers[i].handler != NULL; i++){
	if (handlers[i].type == datalink_type){
            return handlers[i].handler;
        }
    }

    die("sorry - unknown datalink type %d on interface %s", datalink_type, device);
    return NULL;    /* NOTREACHED */
}
