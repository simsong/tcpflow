/*
 * This file is part of tcpflow by Jeremy Elson <jelson@circlemud.org>
 * Initial Release: 7 April 1999.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * $Id: datalink.c,v 1.8 2002/03/29 23:18:51 jelson Exp $
 *
 * $Log: datalink.c,v $
 * Revision 1.8  2002/03/29 23:18:51  jelson
 * oops... fixed typo
 *
 * Revision 1.7  2002/03/29 22:31:16  jelson
 * Added support for ISDN (/dev/ippp0), datalink handler for
 * DLT_LINUX_SLL.  Contributed by Detlef Conradin <dconradin at gmx.net>
 *
 * Revision 1.6  1999/04/21 01:40:13  jelson
 * DLT_NULL fixes, u_char fixes, additions to configure.in, man page update
 *
 * Revision 1.5  1999/04/20 19:39:18  jelson
 * changes to fix broken localhost (DLT_NULL) handling
 *
 * Revision 1.4  1999/04/13 23:17:55  jelson
 * More portability fixes.  All system header files now conditionally
 * included from sysdep.h.
 *
 * Integrated patch from Johnny Tevessen <j.tevessen@gmx.net> for Linux
 * systems still using libc5.
 *
 * Revision 1.3  1999/04/13 01:38:10  jelson
 * Added portability features with 'automake' and 'autoconf'.  Added AUTHORS,
 * NEWS, README, etc files (currently empty) to conform to GNU standards.
 *
 * Various portability fixes, including the FGETPOS/FSETPOS macros; detection
 * of header files using autoconf; restructuring of debugging code to not
 * need vsnprintf.
 *
 */

#include "tcpflow.h"

/* The DLT_NULL packet header is 4 bytes long. It contains a network
 * order 32 bit integer that specifies the family, e.g. AF_INET.
 * DLT_NULL is used by the localhost interface. */
#define	NULL_HDRLEN 4

/* Some systems hasn't defined ETHERTYPE_IPV6 */
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

void dl_null(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;
    uint32_t family = *(uint32_t *)p;;

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
    //memcpy((char *)&family, (char *)p, sizeof(family));
    //family = ntohl(family);
    if (family != AF_INET && family != AF_INET6) {
	DEBUG(6)("warning: received null frame with unknown type (type 0x%x) (AF_INET=%x; AF_INET6=%x)",
		 family,AF_INET,AF_INET6);
	return;
    }
#endif

    //process_packet(h->ts,p + NULL_HDRLEN, caplen - NULL_HDRLEN,flow::NO_VLAN);
    packet_info pi(h->ts,p+NULL_HDRLEN,caplen - NULL_HDRLEN,flow::NO_VLAN);
    process_packet_info(pi);
}



/* Ethernet datalink handler; used by all 10 and 100 mbit/sec
 * ethernet.  We are given the entire ethernet header so we check to
 * make sure it's marked as being IP. */
void dl_ethernet(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;
    struct ether_header *eth_header = (struct ether_header *) p;

    /* Variables to support VLAN */
    int32_t vlan = flow::NO_VLAN;			       /* default is no vlan */
    const u_short *ether_type = &eth_header->ether_type; /* where the ether type is located */
    const u_char *ether_data = p+sizeof(struct ether_header); /* where the data is located */

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte ether frame",
		  caplen, length);
    }

    /* Handle basic VLAN packets */
    if (ntohs(*ether_type) == ETHERTYPE_VLAN) {
	vlan = ntohs(*(u_short *)(p+sizeof(struct ether_header)));
	ether_type += 2;			/* skip past VLAN header (note it skips by 2s) */
	ether_data += 4;			/* skip past VLAN header */
	caplen     -= 4;
    }
  
    if (caplen < sizeof(struct ether_header)) {
	DEBUG(6) ("warning: received incomplete ethernet frame");
	return;
    }

    /* switch on ether type */
    switch (ntohs(*ether_type)){
    case ETHERTYPE_IP:
    case ETHERTYPE_IPV6:
	//process_packet_info(h->ts,ether_data, caplen - sizeof(struct ether_header),vlan);
    {
	packet_info pi(h->ts,ether_data, caplen - sizeof(struct ether_header),vlan);
	process_packet_info(pi);
	return;
    }
#ifdef ETHERTYPE_ARP
    case ETHERTYPE_ARP:
#endif
#ifdef ETHERTYPE_LOOPBACK
    case ETHERTYPE_LOOPBACK:
#endif
#ifdef ETHERTYPE_REVARP
    case ETHERTYPE_REVARP:
#endif
	return;
    default:
	break;
    }

    /* Unknown Ethernet Frame Type */
    DEBUG(6) ("warning: received ethernet frame with unknown type 0x%x", ntohs(eth_header->ether_type));
}

/* The DLT_PPP packet header is 4 bytes long.  We just move past it
 * without parsing it.  It is used for PPP on some OSs (DLT_RAW is
 * used by others; see below) */
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

    //process_packet_info(h->ts,p + PPP_HDRLEN, caplen - PPP_HDRLEN,flow::NO_VLAN);
    packet_info pi(h->ts,p + PPP_HDRLEN, caplen - PPP_HDRLEN,flow::NO_VLAN);
    process_packet_info(pi);
}


/* DLT_RAW: just a raw IP packet, no encapsulation or link-layer
 * headers.  Used for PPP connections under some OSs including Linux
 * and IRIX. */
void dl_raw(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    u_int caplen = h->caplen;
    u_int length = h->len;

    if (length != caplen) {
	DEBUG(6) ("warning: only captured %d bytes of %d byte raw frame",
		  caplen, length);
    }
    //process_packet_info(h->ts,p, caplen,flow::NO_VLAN);
    packet_info pi(h->ts,p, caplen,flow::NO_VLAN);
    process_packet_info(pi);
}

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
  
    //process_packet_info(h->ts,p + SLL_HDR_LEN, caplen - SLL_HDR_LEN,flow::NO_VLAN);
    packet_info pi(h->ts,p + SLL_HDR_LEN, caplen - SLL_HDR_LEN,flow::NO_VLAN);
    process_packet_info(pi);
}


pcap_handler find_handler(int datalink_type, const char *device)
{
    int i;

    struct {
	pcap_handler handler;
	int type;
    } handlers[] = {
	{ dl_null,	DLT_NULL },
#ifdef DLT_RAW /* older versions of libpcap do not have DLT_RAW */
	{ dl_raw,	DLT_RAW },
#endif
	{ dl_ethernet,	DLT_EN10MB },
	{ dl_ethernet,	DLT_IEEE802 },
	{ dl_ppp,	DLT_PPP },
#ifdef DLT_LINUX_SLL
	{ dl_linux_sll, DLT_LINUX_SLL },
#endif
	{ NULL, 0 },
    };

    DEBUG(3) ("looking for handler for datalink type %d for interface %s",
	      datalink_type, device);

    for (i = 0; handlers[i].handler != NULL; i++){
	if (handlers[i].type == datalink_type) return handlers[i].handler;
    }

    die("sorry - unknown datalink type %d on interface %s", datalink_type, device);
    /* NOTREACHED */
    return NULL;
}

