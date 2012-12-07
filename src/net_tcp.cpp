/**
 * net_tcp.cpp: 
 * common functions and definitions related to the Transmission Control Protocol
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "tcpflow.h"
#include "net_ip.h"

#include "net_tcp.h"

// quickly try and get the port out of the packet.  It is assumed that the
// packet is an IPv4 or 6 datagram in an ethernet frame.
// any and all errors simply result in -1 being returned
int net_tcp::get_port(const packet_info &pi)
{
    // keep track of the length of the packet not yet examined
    unsigned int unused_len = pi.caplen;
    if(unused_len < sizeof(struct ether_header)) {
        return -1;
    }

    // only one of these is safe to use!
    const struct ip *ip_header = (struct ip *) pi.data;
    const struct private_ip6_hdr *ip6_header = (struct private_ip6_hdr *) pi.data;

    u_char *ip_data=0;

    switch(ip_header->ip_v){
    case 4:				// IPv4
	if(unused_len < sizeof(struct ip) ||
	   ip_header->ip_p != IPPROTO_TCP) {
	    return -1;
	}
	unused_len -= sizeof(struct ip);
	ip_data = (u_char *) pi.data + sizeof(struct ip);
	break;
    case 6:				// IPv6
	if(unused_len < sizeof(struct private_ip6_hdr) ||
	   ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
	    return -1;
	}
	unused_len -= sizeof(struct private_ip6_hdr);
	ip_data = (u_char *) pi.data + sizeof(struct private_ip6_hdr);
	break;
    default:
	return -1;
    }

    if(unused_len < sizeof(struct tcphdr)) {
        return -1;
    }

    struct tcphdr *tcp_header = (struct tcphdr *) ip_data;

    return ntohs(tcp_header->th_dport);
}
