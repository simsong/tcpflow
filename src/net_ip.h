/**
 * net_ip.h: 
 * common functions and definitions related to the Internet Protocols
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#ifndef NET_IP_H
#define NET_IP_H

#define IPV6_HEADER_LEN 40
#define PORT_HTTP 80
#define PORT_HTTP_ALT_0 8080
#define PORT_HTTP_ALT_1 8000
#define PORT_HTTP_ALT_2 8888
#define PORT_HTTP_ALT_3 81
#define PORT_HTTP_ALT_4 82
#define PORT_HTTP_ALT_5 8090
#define PORT_HTTPS 443

// copied from tcpdemux.cpp - should this be in a header somewhere?
struct private_ip6_hdr {
    union {
	struct ip6_hdrctl {
	    uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
	    uint16_t ip6_un1_plen;	/* payload length */
	    uint8_t  ip6_un1_nxt;	/* next header */
	    uint8_t  ip6_un1_hlim;	/* hop limit */
	} ip6_un1;
	uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
    } ip6_ctlun;
    struct private_in6_addr ip6_src;	/* source address */
    struct private_in6_addr ip6_dst;	/* destination address */
} __attribute__((__packed__));

#endif
