/**********************************************************************
 * file:   wifi_parser.c
 * date:   Sun Mar 12 11:19:46 EST 2006
 * Author: Doug Madory
 **********************************************************************/

#include <iostream>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

using namespace std;

#include "wifipcap.h"

#pragma GCC diagnostic ignored "-Wcast-align"


#include "ether.h"
#include "ethertype.h"
#include "oui.h"
#include "ipproto.h"
#include "extract.h"
#include "icmp.h"
#include "tcp.h"
#include "util.h"
//#include "arp.h"
#include "uni/ieee802_11.h"
#include "uni/ieee802_11_radio.h"
#include "uni/llc.h"

//#include "ieee802_11_radio.h"
#include "cpack.h"

/*max length of an IEEE 802.11 packet*/
#ifndef MAX_LEN_80211
#define MAX_LEN_80211 3000
#endif

/* from ethereal packet-prism.c */
#define pletohs(p)  ((u_int16_t)					\
		     ((u_int16_t)*((const u_int8_t *)(p)+1)<<8|		\
		      (u_int16_t)*((const u_int8_t *)(p)+0)<<0))
#define pntohl(p)   ((u_int32_t)*((const u_int8_t *)(p)+0)<<24|	\
		     (u_int32_t)*((const u_int8_t *)(p)+1)<<16|	\
		     (u_int32_t)*((const u_int8_t *)(p)+2)<<8|	\
		     (u_int32_t)*((const u_int8_t *)(p)+3)<<0)
#define COOK_FRAGMENT_NUMBER(x) ((x) & 0x000F)
#define COOK_SEQUENCE_NUMBER(x) (((x) & 0xFFF0) >> 4)
/* end ethereal code */

/* Sequence number gap */
#define SEQ_GAP(current, last)(0xfff & (current - last))

/* In the following three arrays, even though the QoS subtypes are listed, in the rest of the program
 * the QoS subtypes are treated as "OTHER_TYPES". The file "ieee802_11.h" currently doesn't account for
 * the existence of QoS subtypes. The QoS subtypes might need to be accomodated there in the future.
 */
static const char * mgmt_subtype_text[] = {
    "AssocReq",
    "AssocResp",
    "ReAssocReq",
    "ReAssocResp",
    "ProbeReq",
    "ProbeResp",
    "",
    "",
    "Beacon",
    "ATIM",
    "Disassoc",
    "Auth",
    "DeAuth",
    "Action", /*QoS mgmt_subtype*/
    "",
    ""
};

static const char * ctrl_subtype_text[] = {
    "", "", "", "", "", "", "", "",
    "BlockAckReq", /*QoS ctrl_subtype*/
    "BlockAck",    /*QoS ctrl_subtype*/
    "PS-Poll",
    "RTS",
    "CTS",
    "ACK",
    "CF-End",
    "CF-End+CF-Ack"
};

static const char * data_subtype_text[] = {
    "Data",
    "Data+CF-Ack",
    "Data+CF-Poll",
    "Data+CF-Ack+CF-Poll",
    "Null(no_data)",
    "CF-Ack(no_data)",
    "CF-Poll(no_data)",
    "CF-Ack+CF-Poll(no_data)",
    "QoS_Data", /*QoS data_subtypes from here on*/
    "QoS_Data+CF-Ack",
    "QoS_Data+CF-Poll",
    "QoS_Data+CF-Ack+CF-Poll",
    "QoS_Null(no_data)",
    "",
    "QoS_CF-Poll(no_data)",
    "QoS_CF-Ack+CF-Poll(no_data)"
};

///////////////////////////////////////////////////////////////////////////////

/* Translate Ethernet address, as seen in struct ether_header, to type MAC. */
static inline MAC ether2MAC(const uint8_t * ether)
{
    return MAC(ether);
}

/* Extract header length. */
static u_int8_t extract_header_length(u_int16_t fc)
{
    switch (FC_TYPE(fc)) {
    case T_MGMT:
	return MGMT_HDRLEN;
    case T_CTRL:
	switch (FC_SUBTYPE(fc)) {
	case CTRL_PS_POLL:
	    return CTRL_PS_POLL_HDRLEN;
	case CTRL_RTS:
	    return CTRL_RTS_HDRLEN;
	case CTRL_CTS:
	    return CTRL_CTS_HDRLEN;
	case CTRL_ACK:
	    return CTRL_ACK_HDRLEN;
	case CTRL_CF_END:
	    return CTRL_END_HDRLEN;
	case CTRL_END_ACK:
	    return CTRL_END_ACK_HDRLEN;
	default:
	    return 0;
	}
    case T_DATA:
	return (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
    default:
	return 0;
    }
}

///////////////////////////////////////////////////////////////////////////////

/* These tcp optinos do not have the size octet */
#define ZEROLENOPT(o) ((o) == TCPOPT_EOL || (o) == TCPOPT_NOP)

void parse_tcp_opts(std::list<tcp_opt_t>& opts, const u_char *cp, u_int hlen)
{

    if (hlen == 0) 
	return;

    register u_int i, opt, datalen;
    register u_int len;

    //putchar(' ');
    //ch = '<';
    while (hlen > 0) {
	tcp_opt_t tcpopt;

	//putchar(ch);
	//TCHECK(*cp);
	opt = *cp++;
	if (ZEROLENOPT(opt))
	    len = 1;
	else {
	    //TCHECK(*cp);
	    len = *cp++;	/* total including type, len */
	    if (len < 2 || len > hlen)
		// stop processing on bad opt
		break;
	    --hlen;		/* account for length byte */
	}
	--hlen;			/* account for type byte */
	datalen = 0;

/* Bail if "l" bytes of data are not left or were not captured  */
#define LENCHECK(l) { if ((l) > hlen) break; }

	tcpopt.type = opt;
	tcpopt.data_raw = cp;

	switch (opt) {

	case TCPOPT_MAXSEG:
	    //(void)printf("mss");
	    datalen = 2;
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_16BITS(cp));
	    tcpopt.data.mss = EXTRACT_16BITS(cp);
	    break;
	    
	case TCPOPT_EOL:
	    //(void)printf("eol");
	    break;
	    
	case TCPOPT_NOP:
	    //(void)printf("nop");
	    break;
	    
	case TCPOPT_WSCALE:
	    //(void)printf("wscale");
	    datalen = 1;
	    LENCHECK(datalen);
	    //(void)printf(" %u", *cp);
	    tcpopt.data.wscale = *cp;
	    break;
	    
	case TCPOPT_SACKOK:
	    //(void)printf("sackOK");
	    break;
	    
	case TCPOPT_SACK:
	    datalen = len - 2;
	    if (datalen % 8 != 0) {
		//(void)printf("malformed sack");
	    } else {
		u_int32_t s, e;
		
		//(void)printf("sack %d ", datalen / 8);
		for (i = 0; i < datalen; i += 8) {
		    LENCHECK(i + 4);
		    s = EXTRACT_32BITS(cp + i);
		    LENCHECK(i + 8);
		    e = EXTRACT_32BITS(cp + i + 4);
		    /* XXX leave application to do this translation?
		    if (threv) {
			s -= thseq;
			e -= thseq;
		    } else {
			s -= thack;
			e -= thack;
		    }
		    (void)printf("{%u:%u}", s, e);
		    */
		    tcpopt.data_sack.push_back(std::pair<u_int32_t,u_int32_t>(s,e));
		}
	    }
	    break;
	    
	case TCPOPT_ECHO:
	    //(void)printf("echo");
	    datalen = 4;
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_32BITS(cp));
	    tcpopt.data.echo = EXTRACT_32BITS(cp);
	    break;
	    
	case TCPOPT_ECHOREPLY:
	    //(void)printf("echoreply");
	    datalen = 4;
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_32BITS(cp));
	    tcpopt.data.echoreply = EXTRACT_32BITS(cp);
	    break;
	    
	case TCPOPT_TIMESTAMP:
	    //(void)printf("timestamp");
	    datalen = 8;
	    //LENCHECK(4);
	    //(void)printf(" %u", EXTRACT_32BITS(cp));
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_32BITS(cp + 4));
	    tcpopt.data.timestamp.tsval = EXTRACT_32BITS(cp);
	    tcpopt.data.timestamp.tsecr = EXTRACT_32BITS(cp + 4);
	    break;
	    
	case TCPOPT_CC:
	    //(void)printf("cc");
	    datalen = 4;
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_32BITS(cp));
	    tcpopt.data.cc = EXTRACT_32BITS(cp);
	    break;
	    
	case TCPOPT_CCNEW:
	    //(void)printf("ccnew");
	    datalen = 4;
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_32BITS(cp));
	    tcpopt.data.ccnew = EXTRACT_32BITS(cp);
	    break;
	    
	case TCPOPT_CCECHO:
	    //(void)printf("ccecho");
	    datalen = 4;
	    LENCHECK(datalen);
	    //(void)printf(" %u", EXTRACT_32BITS(cp));
	    tcpopt.data.ccecho = EXTRACT_32BITS(cp);
	    break;
	    
	case TCPOPT_SIGNATURE:
	    //(void)printf("md5:");
	    datalen = TCP_SIGLEN;
	    LENCHECK(datalen);
	    for (i = 0; i < TCP_SIGLEN; ++i)
		//(void)printf("%02x", cp[i]);
		tcpopt.data.signature[i] = cp[i];
	    break;
	    
	default:
	    //(void)printf("opt-%u:", opt);
	    datalen = len - 2;
	    /*
	    for (i = 0; i < datalen; ++i) {
		LENCHECK(i);
		(void)printf("%02x", cp[i]);
	    }
	    */
	    break;
	}
	
	/* Account for data printed */
	cp += datalen;
	hlen -= datalen;
	
	/* Check specification against observed length */
	//++datalen;			/* option octet */
	//if (!ZEROLENOPT(opt))
	//    ++datalen;		/* size octet */
	//if (datalen != len)
	//    (void)printf("[len %d]", len);
	//ch = ',';

	tcpopt.len = datalen;
	opts.push_back(tcpopt);

	if (opt == TCPOPT_EOL)
	    break;
    }
    //putchar('>');

}

void
handle_tcp(const struct timeval& t, WifipcapCallbacks *cbs, 
	   const u_char *bp, u_int length,
	   struct ip4_hdr_t *ip4h, struct ip6_hdr_t *ip6h, int fragmented)
{
    struct tcphdr *tp;
    tp = (struct tcphdr *)bp;
    int hlen;

    // truncated header
    if (length < sizeof(*tp)) {
	cbs->HandleTCP(t, ip4h, ip6h, NULL, NULL, 0, bp, length);
	return;
    }

    hlen = TH_OFF(tp) * 4;

    // bad header length || missing tcp options
    if (hlen < (int)sizeof(*tp) || length < (int)sizeof(*tp) || hlen > (int)length) {
	cbs->HandleTCP(t, ip4h, ip6h, NULL, NULL, 0, bp, length);
	return;
    }

    tcp_hdr_t hdr;
    hdr.sport = EXTRACT_16BITS(&tp->th_sport);
    hdr.dport = EXTRACT_16BITS(&tp->th_dport);
    hdr.seq = EXTRACT_32BITS(&tp->th_seq);
    hdr.ack = EXTRACT_32BITS(&tp->th_ack);
    hdr.dataoff = TH_OFF(tp) * 4;
    hdr.flags = tp->th_flags;
    hdr.win = EXTRACT_16BITS(&tp->th_win);
    hdr.cksum = EXTRACT_16BITS(&tp->th_sum);
    hdr.urgptr = EXTRACT_16BITS(&tp->th_urp);

    //parse_tcp_opts(hdr.opts, bp+sizeof(*tp), hlen-sizeof(*tp));

    cbs->HandleTCP(t, ip4h, ip6h, &hdr, hlen==sizeof(*tp)?NULL:bp+sizeof(*tp), hlen-sizeof(*tp), bp+hlen, length-hlen);
}

void
handle_udp(const struct timeval& t, WifipcapCallbacks *cbs, 
	   const u_char *bp, u_int length,
	   struct ip4_hdr_t *ip4h, struct ip6_hdr_t *ip6h, int fragmented)
{
    struct udphdr *uh;
    uh = (struct udphdr *)bp;

    if (length < sizeof(struct udphdr)) {
	// truncated udp header
	cbs->HandleUDP(t, ip4h, ip6h, NULL, bp, length);
	return;
    }

    udp_hdr_t hdr;
    hdr.sport = EXTRACT_16BITS(&uh->uh_sport);
    hdr.dport = EXTRACT_16BITS(&uh->uh_dport);
    hdr.len   = EXTRACT_16BITS(&uh->uh_ulen);
    hdr.cksum = EXTRACT_16BITS(&uh->uh_sum);

    cbs->HandleUDP(t, ip4h, ip6h, &hdr, bp+sizeof(struct udphdr), length-sizeof(struct udphdr));
}

void
handle_icmp(const struct timeval& t, WifipcapCallbacks *cbs, 
	    const u_char *bp, u_int length,
	    struct ip4_hdr_t *ip4h, struct ip6_hdr_t *ip6h, int fragmented)
{
    struct icmp *dp;
    dp = (struct icmp *)bp;

    if (length < 4) {
	// truncated icmp header
	cbs->HandleICMP(t, ip4h, ip6h, -1, -1, bp, length);
	return;
    }

    cbs->HandleICMP(t, ip4h, ip6h, dp->icmp_type, dp->icmp_code, bp+4, length-4);
}

///////////////////////////////////////////////////////////////////////////////

void handle_ip(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len);
void handle_ip6(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len);

struct ip_print_demux_state {
	struct ip *ip;
	const u_char *cp;
	u_int   len, off;
	u_char  nh;
	int     advance;
};

void
ip_demux(const struct timeval& t, WifipcapCallbacks *cbs, ip4_hdr_t *hdr, struct ip_print_demux_state *ipds, int len)
{
    //struct protoent *proto;

//again:
	switch (ipds->nh) {
	case IPPROTO_TCP:
	    /* pass on the MF bit plus the offset to detect fragments */
	    handle_tcp(t, cbs, ipds->cp, ipds->len, hdr, NULL,
		       ipds->off & (IP_MF|IP_OFFMASK));
	    break;
		
	case IPPROTO_UDP:
	    /* pass on the MF bit plus the offset to detect fragments */
	    handle_udp(t, cbs, ipds->cp, ipds->len, hdr, NULL,
		       ipds->off & (IP_MF|IP_OFFMASK));
	    break;
		
	case IPPROTO_ICMP:
	    /* pass on the MF bit plus the offset to detect fragments */
	    handle_icmp(t, cbs, ipds->cp, ipds->len, hdr, NULL,
			ipds->off & (IP_MF|IP_OFFMASK));
	    break;
		
	case IPPROTO_IPV4:
	    /* DVMRP multicast tunnel (ip-in-ip encapsulation) */
	    //handle_ip(t, cbs, ipds->cp, ipds->len);
	    //break;
	case IPPROTO_IPV6:
	    /* ip6-in-ip encapsulation */
	    //handle_ip6(t, cbs, ipds->cp, ipds->len);
	    //break;
	    
	    ///// Jeff: XXX Some day handle these maybe (see tcpdump code)
	case IPPROTO_AH:
	    /*
		ipds->nh = *ipds->cp;
		ipds->advance = ah_print(ipds->cp);
		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance;
		goto again;
	    */
	case IPPROTO_ESP:
	{
	    /*
		int enh, padlen;
		ipds->advance = esp_print(ndo, ipds->cp, ipds->len,
				    (const u_char *)ipds->ip,
				    &enh, &padlen);
		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance + padlen;
		ipds->nh = enh & 0xff;
		goto again;
	    */
	}
	case IPPROTO_IPCOMP:
	{
	    /*
		int enh;
		ipds->advance = ipcomp_print(ipds->cp, &enh);
		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance;
		ipds->nh = enh & 0xff;
		goto again;
	    */
	}
	case IPPROTO_SCTP:
	    /*
		sctp_print(ipds->cp, (const u_char *)ipds->ip, ipds->len);
		break;
	    */
	case IPPROTO_DCCP:
	    /*
		dccp_print(ipds->cp, (const u_char *)ipds->ip, ipds->len);
		break;
	    */	
	case IPPROTO_PIGP:
		/*
		 * XXX - the current IANA protocol number assignments
		 * page lists 9 as "any private interior gateway
		 * (used by Cisco for their IGRP)" and 88 as
		 * "EIGRP" from Cisco.
		 *
		 * Recent BSD <netinet/in.h> headers define
		 * IP_PROTO_PIGP as 9 and IP_PROTO_IGRP as 88.
		 * We define IP_PROTO_PIGP as 9 and
		 * IP_PROTO_EIGRP as 88; those names better
		 * match was the current protocol number
		 * assignments say.
		 */
	    /*
		igrp_print(ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;
	    */
	case IPPROTO_EIGRP:
	    /*
		eigrp_print(ipds->cp, ipds->len);
		break;
	    */
	case IPPROTO_ND:
	    /*
		ND_PRINT((ndo, " nd %d", ipds->len));
		break;
	    */
	case IPPROTO_EGP:
	    /*
		egp_print(ipds->cp, ipds->len);
		break;
	    */
	case IPPROTO_OSPF:
	    /*
		ospf_print(ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;
	    */
	case IPPROTO_IGMP:
	    /*
		igmp_print(ipds->cp, ipds->len);
		break;
	    */
	case IPPROTO_RSVP:
	    /*
		rsvp_print(ipds->cp, ipds->len);
		break;
	    */
	case IPPROTO_GRE:
		/* do it */
	    /*
		gre_print(ipds->cp, ipds->len);
		break;
	    */
	case IPPROTO_MOBILE:
	    /*
		mobile_print(ipds->cp, ipds->len);
		break;
	    */
	case IPPROTO_PIM:
	    /*
		pim_print(ipds->cp,  ipds->len);
		break;
	    */
	case IPPROTO_VRRP:
	    /*
		vrrp_print(ipds->cp, ipds->len, ipds->ip->ip_ttl);
		break;
	    */
	case IPPROTO_PGM:
	    /*
		pgm_print(ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;
	    */

	default:
	    /*
		if ((proto = getprotobynumber(ipds->nh)) != NULL)
			ND_PRINT((ndo, " %s", proto->p_name));
		else
			ND_PRINT((ndo, " ip-proto-%d", ipds->nh));
		ND_PRINT((ndo, " %d", ipds->len));
	    */
	    cbs->HandleL3Unknown(t, hdr, NULL, ipds->cp, ipds->len);
	    
	    break;
	}
}

void handle_ip(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len)
{
    struct ip_print_demux_state  ipd;
    struct ip_print_demux_state *ipds=&ipd;
    u_int hlen;

    // truncated (in fact, nothing!)
    if (len == 0) {
	cbs->HandleIP(t, NULL, NULL, 0, ptr, len);
	return;
    }

    ipds->ip = (struct ip *)ptr;
    if (IP_V(ipds->ip) != 4) {
	if (IP_V(ipds->ip) == 6) {
	    // wrong link-layer encap!
	    handle_ip6(t, cbs, ptr, len);
	    return;
	}
    }
    if (len < sizeof (struct ip)) {
	// truncated!
	cbs->HandleIP(t, NULL, NULL, 0, ptr, len);
	return;
    }
    hlen = IP_HL(ipds->ip) * 4;
    ipds->len = EXTRACT_16BITS(&ipds->ip->ip_len);
    if (len < (int)ipds->len) {
	// truncated IP
	// this is ok, we'll just report the truncation later
    }
    if (ipds->len < hlen) {
	// missing some ip options!
	cbs->HandleIP(t, NULL, NULL, 0, ptr, len);
    }
    
    ipds->len -= hlen;
    
    ipds->off = EXTRACT_16BITS(&ipds->ip->ip_off);

    struct ip4_hdr_t hdr;
    hdr.ver      = IP_V(ipds->ip);
    hdr.hlen     = IP_HL(ipds->ip) * 4;
    hdr.tos      = ipds->ip->ip_tos;
    hdr.len      = EXTRACT_16BITS(&ipds->ip->ip_len);
    hdr.id       = EXTRACT_16BITS(&ipds->ip->ip_id);
    hdr.df       = (bool)((ipds->off & IP_DF) != 0);
    hdr.mf       = (bool)((ipds->off & IP_MF) != 0);
    hdr.fragoff  = (ipds->off & IP_OFFMASK);
    hdr.ttl      = ipds->ip->ip_ttl;
    hdr.proto    = ipds->ip->ip_p;
    hdr.cksum    = EXTRACT_16BITS(&ipds->ip->ip_sum);
    hdr.src      = ipds->ip->ip_src;
    hdr.dst      = ipds->ip->ip_dst;

    cbs->HandleIP(t, &hdr, hlen==sizeof(struct ip)?NULL:ptr+sizeof(struct ip), hlen-sizeof(struct ip), ptr+hlen, len-hlen);
    
    /*
     * If this is fragment zero, hand it to the next higher
     * level protocol.
     */
    if ((ipds->off & 0x1fff) == 0) {
	ipds->cp = (const u_char *)ipds->ip + hlen;
	ipds->nh = ipds->ip->ip_p;
	
	ip_demux(t, cbs, &hdr, ipds, len);
    } else {
	// This is a fragment of a previous packet. can't demux it
	return;
    }
}

void handle_ip6(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len)
{
    const struct ip6_hdr *ip6;
    if (len < sizeof (struct ip6_hdr)) {
	cbs->HandleIP6(t, NULL, ptr, len);
	return;
    }
    ip6 = (const struct ip6_hdr *)ptr;

    ip6_hdr_t hdr;
    memcpy(&hdr, ip6, sizeof(hdr));
    hdr.ip6_plen = EXTRACT_16BITS(&ip6->ip6_plen);
    hdr.ip6_flow = EXTRACT_32BITS(&ip6->ip6_flow);

    cbs->HandleIP6(t, &hdr, ptr+sizeof(hdr), len-sizeof(hdr));

    int nh = ip6->ip6_nxt;
    switch(nh) {
    case IPPROTO_TCP:
	handle_tcp(t, cbs, ptr+sizeof(ip6_hdr), len-sizeof(ip6_hdr), 
		   NULL, &hdr, 0);
	break;
    case IPPROTO_UDP:
	handle_udp(t, cbs, ptr+sizeof(ip6_hdr), len-sizeof(ip6_hdr), 
		   NULL, &hdr, 0);
	break;
    default:
	cbs->HandleL3Unknown(t, NULL, &hdr, 
			     ptr+sizeof(ip6_hdr), len-sizeof(ip6_hdr));
	break;
    }
}

void handle_arp(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len)
{
    struct arp_pkthdr *ap;
    //u_short pro, hrd, op;

    if (len < sizeof(struct arp_pkthdr)) {
	cbs->HandleARP(t, NULL, ptr, len);
	return;
    }

    ap = (struct arp_pkthdr *)ptr;
    cbs->HandleARP(t, ap, ptr+ARP_HDRLEN, len-ARP_HDRLEN);
}

///////////////////////////////////////////////////////////////////////////////

void handle_ether(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len)
{
    WifipcapCallbacks::ether_hdr_t hdr;

    hdr.da = ether2MAC(ptr);
    hdr.sa = ether2MAC(ptr+6);
    hdr.type = EXTRACT_16BITS(ptr + 12);

    ptr += 14;
    len -= 14;

    cbs->HandleEthernet(t, &hdr, ptr, len);

    switch (hdr.type) {
    case ETHERTYPE_IP:
	handle_ip(t, cbs, ptr, len);
	return;
    case ETHERTYPE_IPV6:
	handle_ip6(t, cbs, ptr, len);
	return;
    case ETHERTYPE_ARP:
	handle_arp(t, cbs, ptr, len);
	return;
    default:
	cbs->HandleL2Unknown(t, hdr.type, ptr, len);
	return;
    }
}

void handle_llc(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len)
{
    if (len < 7) {
	// truncated header!
	cbs->HandleLLC(t, NULL, ptr, len);
	return;
    }

    // Jeff: XXX This assumes ethernet->80211 llc encapsulation and is
    // NOT correct for all forms of LLC encapsulation. See print-llc.c
    // in tcpdump for a more complete parsing of this header.

    llc_hdr_t hdr;
    hdr.dsap = EXTRACT_LE_8BITS(ptr);
    hdr.ssap = EXTRACT_LE_8BITS(ptr + 1);
    hdr.control = EXTRACT_LE_8BITS(ptr + 2);
    hdr.oui = EXTRACT_24BITS(ptr + 3);
    hdr.type = EXTRACT_16BITS(ptr + 6);

    if (hdr.oui != OUI_ENCAP_ETHER && hdr.oui != OUI_CISCO_90) {
	cbs->HandleLLCUnknown(t, ptr, len);
	return;
    }

    ptr += 8;
    len -= 8;

    cbs->HandleLLC(t, &hdr, ptr, len);

    switch (hdr.type) {
    case ETHERTYPE_IP:
	handle_ip(t, cbs, ptr, len);
	return;
    case ETHERTYPE_IPV6:
	handle_ip6(t, cbs, ptr, len);
	return;
    case ETHERTYPE_ARP:
	handle_arp(t, cbs, ptr, len);
	return;
    default:
	cbs->HandleL2Unknown(t, hdr.type, ptr, len);
	return;
    }
}

void handle_wep(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *ptr, int len)
{
    // Jeff: XXX handle TKIP/CCMP ? how can we demultiplex different
    // protection protocols?

    struct wep_hdr_t hdr;
    u_int32_t iv;

    if (len < IEEE802_11_IV_LEN + IEEE802_11_KID_LEN) {
	// truncated!
	cbs->HandleWEP(t, NULL, ptr, len);
	return;
    }

    iv = EXTRACT_LE_32BITS(ptr);
    hdr.iv = IV_IV(iv);
    hdr.pad = IV_PAD(iv);
    hdr.keyid = IV_KEYID(iv);

    cbs->HandleWEP(t, &hdr, ptr, len);
}
#endif

///////////////////////////////////////////////////////////////////////////////

static const char *auth_alg_text[]={"Open System","Shared Key","EAP"};
#define NUM_AUTH_ALGS	(sizeof auth_alg_text / sizeof auth_alg_text[0])

static const char *status_text[] = {
	"Succesful",  /*  0  */
	"Unspecified failure",  /*  1  */
	"Reserved",	  /*  2  */
	"Reserved",	  /*  3  */
	"Reserved",	  /*  4  */
	"Reserved",	  /*  5  */
	"Reserved",	  /*  6  */
	"Reserved",	  /*  7  */
	"Reserved",	  /*  8  */
	"Reserved",	  /*  9  */
	"Cannot Support all requested capabilities in the Capability Information field",	  /*  10  */
	"Reassociation denied due to inability to confirm that association exists",	  /*  11  */
	"Association denied due to reason outside the scope of the standard",	  /*  12  */
	"Responding station does not support the specified authentication algorithm ",	  /*  13  */
	"Received an Authentication frame with authentication transaction " \
		"sequence number out of expected sequence",	  /*  14  */
	"Authentication rejected because of challenge failure",	  /*  15 */
	"Authentication rejected due to timeout waiting for next frame in sequence",	  /*  16 */
	"Association denied because AP is unable to handle additional associated stations",	  /*  17 */
	"Association denied due to requesting station not supporting all of the " \
		"data rates in BSSBasicRateSet parameter",	  /*  18 */
};
#define NUM_STATUSES	(sizeof status_text / sizeof status_text[0])

static const char *reason_text[] = {
	"Reserved", /* 0 */
	"Unspecified reason", /* 1 */
	"Previous authentication no longer valid",  /* 2 */
	"Deauthenticated because sending station is leaving (or has left) IBSS or ESS", /* 3 */
	"Disassociated due to inactivity", /* 4 */
	"Disassociated because AP is unable to handle all currently associated stations", /* 5 */
	"Class 2 frame received from nonauthenticated station", /* 6 */
	"Class 3 frame received from nonassociated station", /* 7 */
	"Disassociated because sending station is leaving (or has left) BSS", /* 8 */
	"Station requesting (re)association is not authenticated with responding station", /* 9 */
};
#define NUM_REASONS	(sizeof reason_text / sizeof reason_text[0])

const char *Wifipcap::WifiUtil::MgmtAuthAlg2Txt(uint v) {
    return v < NUM_AUTH_ALGS ? auth_alg_text[v] : "Unknown";
}
const char *Wifipcap::WifiUtil::MgmtStatusCode2Txt(uint v) {
    return v < NUM_STATUSES ? status_text[v] : "Reserved";
}
const char *Wifipcap::WifiUtil::MgmtReasonCode2Txt(uint v) {
    return v < NUM_REASONS ? reason_text[v] : "Reserved";
}

const char *Wifipcap::WifiUtil::EtherType2Txt(uint t) {
    return tok2str(ethertype_values,"Unknown", t);
}

///////////////////////////////////////////////////////////////////////////////

// Jeff: HACK -- tcpdump uses a global variable to check truncation
#define TTEST2(_p, _l) ((const u_char *)&(_p) - p + (_l) <= len) 

static void
parse_elements(struct mgmt_body_t *pbody, const u_char *p, int offset, int len)
{
	/*
	 * We haven't seen any elements yet.
	 */
	pbody->challenge_status = NOT_PRESENT;
	pbody->ssid_status = NOT_PRESENT;
	pbody->rates_status = NOT_PRESENT;
	pbody->ds_status = NOT_PRESENT;
	pbody->cf_status = NOT_PRESENT;
	pbody->tim_status = NOT_PRESENT;

	for (;;) {
		if (!TTEST2(*(p + offset), 1))
			return;
		switch (*(p + offset)) {
		case E_SSID:
			/* Present, possibly truncated */
			pbody->ssid_status = TRUNCATED;
			if (!TTEST2(*(p + offset), 2))
				return;
			memcpy(&pbody->ssid, p + offset, 2);
			offset += 2;
			if (pbody->ssid.length != 0) {
				if (pbody->ssid.length >
				    sizeof(pbody->ssid.ssid) - 1)
					return;
				if (!TTEST2(*(p + offset), pbody->ssid.length))
					return;
				memcpy(&pbody->ssid.ssid, p + offset,
				    pbody->ssid.length);
				offset += pbody->ssid.length;
			}
			pbody->ssid.ssid[pbody->ssid.length] = '\0';
			/* Present and not truncated */
			pbody->ssid_status = PRESENT;
			break;
		case E_CHALLENGE:
			/* Present, possibly truncated */
			pbody->challenge_status = TRUNCATED;
			if (!TTEST2(*(p + offset), 2))
				return;
			memcpy(&pbody->challenge, p + offset, 2);
			offset += 2;
			if (pbody->challenge.length != 0) {
				if (pbody->challenge.length >
				    sizeof(pbody->challenge.text) - 1)
					return;
				if (!TTEST2(*(p + offset), pbody->challenge.length))
					return;
				memcpy(&pbody->challenge.text, p + offset,
				    pbody->challenge.length);
				offset += pbody->challenge.length;
			}
			pbody->challenge.text[pbody->challenge.length] = '\0';
			/* Present and not truncated */
			pbody->challenge_status = PRESENT;
			break;
		case E_RATES:
			/* Present, possibly truncated */
			pbody->rates_status = TRUNCATED;
			if (!TTEST2(*(p + offset), 2))
				return;
			memcpy(&(pbody->rates), p + offset, 2);
			offset += 2;
			if (pbody->rates.length != 0) {
				if (pbody->rates.length > sizeof pbody->rates.rate)
					return;
				if (!TTEST2(*(p + offset), pbody->rates.length))
					return;
				memcpy(&pbody->rates.rate, p + offset,
				    pbody->rates.length);
				offset += pbody->rates.length;
			}
			/* Present and not truncated */
			pbody->rates_status = PRESENT;
			break;
		case E_DS:
			/* Present, possibly truncated */
			pbody->ds_status = TRUNCATED;
			if (!TTEST2(*(p + offset), 3))
				return;
			memcpy(&pbody->ds, p + offset, 3);
			offset += 3;
			/* Present and not truncated */
			pbody->ds_status = PRESENT;
			break;
		case E_CF:
			/* Present, possibly truncated */
			pbody->cf_status = TRUNCATED;
			if (!TTEST2(*(p + offset), 8))
				return;
			memcpy(&pbody->cf, p + offset, 8);
			offset += 8;
			/* Present and not truncated */
			pbody->cf_status = PRESENT;
			break;
		case E_TIM:
			/* Present, possibly truncated */
			pbody->tim_status = TRUNCATED;
			if (!TTEST2(*(p + offset), 2))
				return;
			memcpy(&pbody->tim, p + offset, 2);
			offset += 2;
			if (!TTEST2(*(p + offset), 3))
				return;
			memcpy(&pbody->tim.count, p + offset, 3);
			offset += 3;

			if (pbody->tim.length <= 3)
				break;
			if (pbody->rates.length > sizeof pbody->tim.bitmap)
				return;
			if (!TTEST2(*(p + offset), pbody->tim.length - 3))
				return;
			memcpy(pbody->tim.bitmap, p + (pbody->tim.length - 3),
			    (pbody->tim.length - 3));
			offset += pbody->tim.length - 3;
			/* Present and not truncated */
			pbody->tim_status = PRESENT;
			break;
		default:
#if 0
			printf("(1) unhandled element_id (%d)  ",
			    *(p + offset) );
#endif
			if (!TTEST2(*(p + offset), 2))
				return;
			if (!TTEST2(*(p + offset + 2), *(p + offset + 1)))
				return;
			offset += *(p + offset + 1) + 2;
			break;
		}
	}
}

/*********************************************************************************
 * Print Handle functions for the management frame types
 *********************************************************************************/

static int
handle_beacon(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
	    IEEE802_11_CAPINFO_LEN))
		return 0;
	memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
	offset += IEEE802_11_TSTAMP_LEN;
	pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_BCNINT_LEN;
	pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_CAPINFO_LEN;

	parse_elements(&pbody, p, offset, len);

	/*
	PRINT_SSID(pbody);
	PRINT_RATES(pbody);
	printf(" %s",
	    CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");
	PRINT_DS_CHANNEL(pbody);
	*/
	cbs->Handle80211MgmtBeacon(t, pmh, &pbody);

	return 1;
}

static int
handle_assoc_request(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_CAPINFO_LEN + IEEE802_11_LISTENINT_LEN))
		return 0;
	pbody.capability_info = EXTRACT_LE_16BITS(p);
	offset += IEEE802_11_CAPINFO_LEN;
	pbody.listen_interval = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_LISTENINT_LEN;

	parse_elements(&pbody, p, offset, len);

	/*
	PRINT_SSID(pbody);
	PRINT_RATES(pbody);
	*/
	cbs->Handle80211MgmtAssocRequest(t, pmh, &pbody);

	return 1;
}

static int
handle_assoc_response(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len, bool reassoc = false)
{
	struct mgmt_body_t pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_CAPINFO_LEN + IEEE802_11_STATUS_LEN +
	    IEEE802_11_AID_LEN))
		return 0;
	pbody.capability_info = EXTRACT_LE_16BITS(p);
	offset += IEEE802_11_CAPINFO_LEN;
	pbody.status_code = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_STATUS_LEN;
	pbody.aid = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_AID_LEN;

	parse_elements(&pbody, p, offset, len);

	/*
	printf(" AID(%x) :%s: %s", ((u_int16_t)(pbody.aid << 2 )) >> 2 ,
	    CAPABILITY_PRIVACY(pbody.capability_info) ? " PRIVACY " : "",
	    (pbody.status_code < NUM_STATUSES
		? status_text[pbody.status_code]
		: "n/a"));
	*/
	if (!reassoc)
	    cbs->Handle80211MgmtAssocResponse(t, pmh, &pbody);
	else
	    cbs->Handle80211MgmtReassocResponse(t, pmh, &pbody);

	return 1;
}

static int
handle_reassoc_request(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_CAPINFO_LEN + IEEE802_11_LISTENINT_LEN +
	    IEEE802_11_AP_LEN))
		return 0;
	pbody.capability_info = EXTRACT_LE_16BITS(p);
	offset += IEEE802_11_CAPINFO_LEN;
	pbody.listen_interval = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_LISTENINT_LEN;
	memcpy(&pbody.ap, p+offset, IEEE802_11_AP_LEN);
	offset += IEEE802_11_AP_LEN;

	parse_elements(&pbody, p, offset, len);

	/*
	PRINT_SSID(pbody);
	printf(" AP : %s", etheraddr_string( pbody.ap ));
	*/
	cbs->Handle80211MgmtReassocRequest(t, pmh, &pbody);

	return 1;
}

static int
handle_reassoc_response(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	/* Same as a Association Reponse */
    return handle_assoc_response(t, cbs, pmh, p, len, true);
}

static int
handle_probe_request(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t  pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	parse_elements(&pbody, p, offset, len);

	/*
	PRINT_SSID(pbody);
	PRINT_RATES(pbody);
	*/
	cbs->Handle80211MgmtProbeRequest(t, pmh, &pbody);

	return 1;
}

static int
handle_probe_response(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t  pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
	    IEEE802_11_CAPINFO_LEN))
		return 0;

	memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
	offset += IEEE802_11_TSTAMP_LEN;
	pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_BCNINT_LEN;
	pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
	offset += IEEE802_11_CAPINFO_LEN;

	parse_elements(&pbody, p, offset, len);

	/*
	PRINT_SSID(pbody);
	PRINT_RATES(pbody);
	PRINT_DS_CHANNEL(pbody);
	*/
	cbs->Handle80211MgmtProbeResponse(t, pmh, &pbody);

	return 1;
}

static int
handle_atim(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
    /* the frame body for ATIM is null. */

    cbs->Handle80211MgmtATIM(t, pmh);

    return 1;
}

static int
handle_disassoc(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t  pbody;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_REASON_LEN))
		return 0;
	pbody.reason_code = EXTRACT_LE_16BITS(p);

	/*
	printf(": %s",
	    (pbody.reason_code < NUM_REASONS)
		? reason_text[pbody.reason_code]
		: "Reserved" );
	*/
	cbs->Handle80211MgmtDisassoc(t, pmh, &pbody);

	return 1;
}

static int
handle_auth(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t  pbody;
	int offset = 0;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, 6))
		return 0;
	pbody.auth_alg = EXTRACT_LE_16BITS(p);
	offset += 2;
	pbody.auth_trans_seq_num = EXTRACT_LE_16BITS(p + offset);
	offset += 2;
	pbody.status_code = EXTRACT_LE_16BITS(p + offset);
	offset += 2;

	parse_elements(&pbody, p, offset, len);

	/*
	if ((pbody.auth_alg == 1) &&
	    ((pbody.auth_trans_seq_num == 2) ||
	     (pbody.auth_trans_seq_num == 3))) {
		printf(" (%s)-%x [Challenge Text] %s",
		    (pbody.auth_alg < NUM_AUTH_ALGS)
			? auth_alg_text[pbody.auth_alg]
			: "Reserved",
		    pbody.auth_trans_seq_num,
		    ((pbody.auth_trans_seq_num % 2)
		        ? ((pbody.status_code < NUM_STATUSES)
			       ? status_text[pbody.status_code]
			       : "n/a") : ""));
		return 1;
	}
	printf(" (%s)-%x: %s",
	    (pbody.auth_alg < NUM_AUTH_ALGS)
		? auth_alg_text[pbody.auth_alg]
		: "Reserved",
	    pbody.auth_trans_seq_num,
	    (pbody.auth_trans_seq_num % 2)
	        ? ((pbody.status_code < NUM_STATUSES)
		    ? status_text[pbody.status_code]
	            : "n/a")
	        : "");
	*/
	cbs->Handle80211MgmtAuth(t, pmh, &pbody);

	return 1;
}

static int
handle_deauth(const struct timeval& t, WifipcapCallbacks *cbs, const struct mgmt_header_t *pmh, const u_char *p, int len)
{
	struct mgmt_body_t  pbody;
	int offset = 0;
	const char *reason = NULL;

	memset(&pbody, 0, sizeof(pbody));

	if (!TTEST2(*p, IEEE802_11_REASON_LEN))
		return 0;
	pbody.reason_code = EXTRACT_LE_16BITS(p);
	offset += IEEE802_11_REASON_LEN;

	reason = (pbody.reason_code < NUM_REASONS)
			? reason_text[pbody.reason_code]
			: "Reserved";

	if (eflag) {
		printf(": %s", reason);
	} else {
		printf(" (%s): %s", etheraddr_string(pmh->sa), reason);
	}
	cbs->Handle80211MgmtDeauth(t, pmh, &pbody);

	return 1;
}


/*********************************************************************************
 * Print Body funcs
 *********************************************************************************/


int
decode_mgmt_body(const struct timeval& t, WifipcapCallbacks *cbs, u_int16_t fc, struct mgmt_header_t *pmh, const u_char *p, int len)
{
	switch (FC_SUBTYPE(fc)) {
	case ST_ASSOC_REQUEST:
	    return handle_assoc_request(t, cbs, pmh, p, len);
	case ST_ASSOC_RESPONSE:
	    return handle_assoc_response(t, cbs, pmh, p, len);
	case ST_REASSOC_REQUEST:
	    return handle_reassoc_request(t, cbs, pmh, p, len);
	case ST_REASSOC_RESPONSE:
	    return handle_reassoc_response(t, cbs, pmh, p, len);
	case ST_PROBE_REQUEST:
	    return handle_probe_request(t, cbs, pmh, p, len);
	case ST_PROBE_RESPONSE:
	    return handle_probe_response(t, cbs, pmh, p, len);
	case ST_BEACON:
	    return handle_beacon(t, cbs, pmh, p, len);
	case ST_ATIM:
	    return handle_atim(t, cbs, pmh, p, len);
	case ST_DISASSOC:
	    return handle_disassoc(t, cbs, pmh, p, len);
	case ST_AUTH:
	    if (len < 3) {
		return 0;
	    }
	    if ((p[0] == 0 ) && (p[1] == 0) && (p[2] == 0)) {
		//printf("Authentication (Shared-Key)-3 ");
		cbs->Handle80211MgmtAuthSharedKey(t, pmh, p, len);
		return 0;
	    }
	    return handle_auth(t, cbs, pmh, p, len);
	case ST_DEAUTH:
	    return handle_deauth(t, cbs, pmh, p, len);
	    break;
	default:
	    return 0;
	}
}

int decode_mgmt_frame(const struct timeval& t, WifipcapCallbacks *cbs, const u_char * ptr, int len, u_int16_t fc, u_int8_t hdrlen, bool fcs_ok)
{
    mgmt_header_t hdr;

    u_int16_t seq_ctl;

    hdr.da = ether2MAC(ptr + 4);
    hdr.sa = ether2MAC(ptr + 10);
    hdr.bssid = ether2MAC(ptr + 16);

    hdr.duration = EXTRACT_LE_16BITS(ptr+2);

    seq_ctl = pletohs(ptr + 22);

    hdr.seq = COOK_SEQUENCE_NUMBER(seq_ctl);
    hdr.frag = COOK_FRAGMENT_NUMBER(seq_ctl);

    cbs->Handle80211(t, fc, hdr.sa, hdr.da, MAC::null, MAC::null, ptr, len, fcs_ok);

    int ret = decode_mgmt_body(t, cbs, fc, &hdr, ptr+MGMT_HDRLEN, len-MGMT_HDRLEN);
    if (!ret) {
	cbs->Handle80211Unknown(t, fc, ptr, len);
	return 0;
    }

    return 0;
}

int decode_data_frame(const struct timeval& t, WifipcapCallbacks *cbs, const u_char * ptr, int len, u_int16_t fc, bool fcs_ok)
{

    u_int16_t seq_ctl;
    u_int16_t seq;
    u_int8_t  frag;

    u_int16_t du = EXTRACT_LE_16BITS(ptr+2);        //duration

    seq_ctl = pletohs(ptr + 22);
    seq = COOK_SEQUENCE_NUMBER(seq_ctl);
    frag = COOK_FRAGMENT_NUMBER(seq_ctl);

    bool body = true;
    int hdrlen;

    if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	/* ad hoc IBSS */
	data_hdr_ibss_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.seq = seq;
	hdr.frag = frag;
	cbs->Handle80211(t, fc, MAC::null, MAC::null, MAC::null, MAC::null, ptr, len, fcs_ok);
	// XXX fcs
	cbs->Handle80211DataIBSS(t, &hdr, ptr+DATA_HDRLEN, len-DATA_HDRLEN);
	hdrlen = DATA_HDRLEN;
	body = false;
    } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	/* frame from AP to STA */
	data_hdr_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.seq = seq;
	hdr.frag = frag;
	hdr.sa = ether2MAC(ptr + 16);
	hdr.da = ether2MAC(ptr + 4);
	hdr.bssid = ether2MAC(ptr + 10);
	cbs->Handle80211(t, fc, hdr.sa, hdr.da, MAC::null, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211DataFromAP(t, &hdr, ptr+DATA_HDRLEN, len-DATA_HDRLEN);
	hdrlen = DATA_HDRLEN;
    } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	/* frame from STA to AP */
	data_hdr_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.seq = seq;
	hdr.frag = frag;
	hdr.sa = ether2MAC(ptr + 10);
	hdr.da = ether2MAC(ptr + 16);
	hdr.bssid = ether2MAC(ptr + 4);
	cbs->Handle80211(t, fc, hdr.sa, hdr.da, MAC::null, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211DataToAP(t, &hdr, ptr+DATA_HDRLEN, len-DATA_HDRLEN);
	hdrlen = DATA_HDRLEN;
    } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	/* WDS */
	data_hdr_wds_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.seq = seq;
	hdr.frag = frag;
	hdr.ra = ether2MAC(ptr+4);
	hdr.ta = ether2MAC(ptr+10);
	hdr.da = ether2MAC(ptr+16);
	hdr.da = ether2MAC(ptr+24);
	cbs->Handle80211(t, fc, hdr.sa, hdr.da, hdr.ra, hdr.ta, ptr, len, fcs_ok);
	cbs->Handle80211DataWDS(t, &hdr, ptr+DATA_WDS_HDRLEN, len-DATA_WDS_HDRLEN);
	hdrlen = DATA_WDS_HDRLEN;
    }

    if (body) {
	if (FC_WEP(fc)) {
	    handle_wep(t, cbs, ptr+hdrlen, len-hdrlen-4 /* FCS */);
	} else {
	    handle_llc(t, cbs, ptr+hdrlen, len-hdrlen-4 /* FCS */);
	}
    }

    return 0;
}


int decode_ctrl_frame(const struct timeval& t, WifipcapCallbacks *cbs, const u_char * ptr, int len, u_int16_t fc, bool fcs_ok)
{
    u_int16_t du = EXTRACT_LE_16BITS(ptr+2);        //duration

    switch (FC_SUBTYPE(fc)) {
    case CTRL_PS_POLL: {
	ctrl_ps_poll_t hdr;
	hdr.fc = fc;
	hdr.aid = du;
	hdr.bssid = ether2MAC(ptr+4);
	hdr.ta = ether2MAC(ptr+10);
	cbs->Handle80211(t, fc, MAC::null, MAC::null, MAC::null, hdr.ta, ptr, len, fcs_ok);
	cbs->Handle80211CtrlPSPoll(t, &hdr);
	break;
    }
    case CTRL_RTS: {
	ctrl_rts_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra = ether2MAC(ptr+4);
	hdr.ta = ether2MAC(ptr+10);
	cbs->Handle80211(t, fc, MAC::null, MAC::null, hdr.ra, hdr.ta, ptr, len, fcs_ok);
	cbs->Handle80211CtrlRTS(t, &hdr);
	break;
    }
    case CTRL_CTS: {
	ctrl_cts_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra = ether2MAC(ptr+4);
	cbs->Handle80211(t, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211CtrlCTS(t, &hdr);
	break;
    }
    case CTRL_ACK: {
	ctrl_ack_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra = ether2MAC(ptr+4);
	cbs->Handle80211(t, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211CtrlAck(t, &hdr);
	break;
    }
    case CTRL_CF_END: {
	ctrl_end_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra = ether2MAC(ptr+4);
	hdr.bssid = ether2MAC(ptr+10);
	cbs->Handle80211(t, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211CtrlCFEnd(t, &hdr);
	break;
    }
    case CTRL_END_ACK: {	
	ctrl_end_ack_t hdr;
	hdr.fc = fc;
	hdr.duration = du;
	hdr.ra = ether2MAC(ptr+4);
	hdr.bssid = ether2MAC(ptr+10);
	cbs->Handle80211(t, fc, MAC::null, MAC::null, hdr.ra, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211CtrlEndAck(t, &hdr);
	break;
    }
    default: {
	cbs->Handle80211(t, fc, MAC::null, MAC::null, MAC::null, MAC::null, ptr, len, fcs_ok);
	cbs->Handle80211Unknown(t, fc, ptr, len);
	return -1;
	//add the case statements for QoS control frames once ieee802_11.h is updated
    }
    }


    return 0;
}

//extern guint32 crc32_802(const guint8 *buf, guint len);

#ifndef roundup2
#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

void handle_80211(const struct timeval& t, WifipcapCallbacks *cbs, const u_char * packet, int len, int pad = 0) 
{
    if (len < 2) {
	cbs->Handle80211(t, 0, MAC::null, MAC::null, MAC::null, MAC::null, packet, len, false);
	cbs->Handle80211Unknown(t, -1, packet, len);
	return;
    }

    u_int16_t fc = EXTRACT_LE_16BITS(packet);       //frame control
    u_int hdrlen = extract_header_length(fc);
    if (pad)
	hdrlen = roundup2(hdrlen, 4);

    if (len < IEEE802_11_FC_LEN || len < (int)hdrlen) {
	cbs->Handle80211Unknown(t, fc, packet, len);
	return;
    }

    bool fcs_ok = false;
    if (cbs->Check80211FCS()) {
	if (len < (int)hdrlen + 4) {
	    //cerr << "too short to have fcs!" << endl;
	} else {
	    // assume fcs is last 4 bytes (?)
	    u_int32_t fcs_sent = EXTRACT_32BITS(packet+len-4);
	    u_int32_t fcs = crc32_802(packet, len-4);

	    /*
	    if (fcs != fcs_sent) {
		cerr << "bad fcs: ";
		fprintf (stderr, "%08x != %08x\n", fcs_sent, fcs); 
	    }
	    */
	    
	    fcs_ok = (fcs == fcs_sent);
	}
    }

    // fill in current_frame: type, sn
    switch (FC_TYPE(fc)) {
    case T_MGMT:
	if(decode_mgmt_frame(t, cbs, packet, len, fc, hdrlen, fcs_ok)<0)
	    return;
	break;
    case T_DATA:
	if(decode_data_frame(t, cbs, packet, len, fc, fcs_ok)<0)
	    return;
	break;
    case T_CTRL:
	if(decode_ctrl_frame(t, cbs, packet, len, fc, fcs_ok)<0)
	    return;
	break;
    default:
	cbs->Handle80211(t, fc, MAC::null, MAC::null, MAC::null, MAC::null, packet, len, fcs_ok);
	cbs->Handle80211Unknown(t, fc, packet, len);
	return;
    }
}

static int
print_radiotap_field(struct cpack_state *s, u_int32_t bit, int *pad, radiotap_hdr *hdr)
{
	union {
		int8_t		i8;
		u_int8_t	u8;
		int16_t		i16;
		u_int16_t	u16;
		u_int32_t	u32;
		u_int64_t	u64;
	} u, u2;
	int rc;

	switch (bit) {
	case IEEE80211_RADIOTAP_FLAGS:
		rc = cpack_uint8(s, &u.u8);
		if (u.u8 & IEEE80211_RADIOTAP_F_DATAPAD)
			*pad = 1;
		break;
	case IEEE80211_RADIOTAP_RATE:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_ANTENNA:
		rc = cpack_uint8(s, &u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		rc = cpack_int8(s, &u.i8);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		rc = cpack_uint16(s, &u.u16);
		if (rc != 0)
			break;
		rc = cpack_uint16(s, &u2.u16);
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
		rc = cpack_uint16(s, &u.u16);
		break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		rc = cpack_uint8(s, &u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		rc = cpack_int8(s, &u.i8);
		break;
	case IEEE80211_RADIOTAP_TSFT:
		rc = cpack_uint64(s, &u.u64);
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
	    rc = cpack_uint16(s, &u.u16);
	    break;
	case IEEE80211_RADIOTAP_TX_FLAGS:
	    rc = cpack_uint16(s, &u.u16);
	    break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	    rc = cpack_uint8(s, &u.u8);
	    break;
	case IEEE80211_RADIOTAP_DATA_RETRIES:
	    rc = cpack_uint8(s, &u.u8);
	    break;
	default:
		/* this bit indicates a field whose
		 * size we do not know, so we cannot
		 * proceed.
		 */
		//printf("[0x%08x] ", bit);
	    fprintf(stderr, "wifipcap: unknown radiotap bit: %d\n", bit);
	    return -1;
	}

	if (rc != 0) {
	    //printf("[|802.11]");
	    fprintf(stderr, "wifipcap: truncated radiotap header for bit: %d\n", bit);
	    return rc;
	}

	switch (bit) {
	case IEEE80211_RADIOTAP_CHANNEL:
	    //printf("%u MHz ", u.u16);
	    if (u2.u16 != 0)
		//printf("(0x%04x) ", u2.u16);
		hdr->has_channel = true;
		hdr->channel = u2.u16;
	    break;
	case IEEE80211_RADIOTAP_FHSS:
	    //printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
	    hdr->has_fhss = true;
	    hdr->fhss_fhset = u.u16 & 0xff;
	    hdr->fhss_fhpat = (u.u16 >> 8) & 0xff;
	    break;
	case IEEE80211_RADIOTAP_RATE:
	    //PRINT_RATE("", u.u8, " Mb/s ");
	    hdr->has_rate = true;
	    hdr->rate = u.u8;
	    break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	    //printf("%ddB signal ", u.i8);
	    hdr->has_signal_dbm = true;
	    hdr->signal_dbm = u.i8;
	    break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	    //printf("%ddB noise ", u.i8);
	    hdr->has_noise_dbm = true;
	    hdr->noise_dbm = u.i8;
	    break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	    //printf("%ddB signal ", u.u8);
	    hdr->has_signal_db = true;
	    hdr->signal_db = u.u8;
	    break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	    //printf("%ddB noise ", u.u8);
	    hdr->has_noise_db = true;
	    hdr->noise_db = u.u8;
	    break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	    //printf("%u sq ", u.u16);
	    hdr->has_quality = true;
	    hdr->quality = u.u16;
	    break;
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	    //printf("%d tx power ", -(int)u.u16);
	    hdr->has_txattenuation = true;
	    hdr->txattenuation = -(int)u.u16;
	    break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	    //printf("%ddB tx power ", -(int)u.u8);
	    hdr->has_txattenuation_db = true;
	    hdr->txattenuation_db = -(int)u.u8;
	    break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	    //printf("%ddBm tx power ", u.i8);
	    hdr->has_txpower_dbm = true;
	    hdr->txpower_dbm = u.i8;
	    break;
	case IEEE80211_RADIOTAP_FLAGS:
	    hdr->has_flags = true;
		if (u.u8 & IEEE80211_RADIOTAP_F_CFP)
		    //printf("cfp ");
		    hdr->flags_cfp = true;
		if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE)
		    //printf("short preamble ");
		    hdr->flags_short_preamble = true;
		if (u.u8 & IEEE80211_RADIOTAP_F_WEP)
		    //printf("wep ");
		    hdr->flags_wep = true;
		if (u.u8 & IEEE80211_RADIOTAP_F_FRAG)
		    //printf("fragmented ");
		    hdr->flags_fragmented = true;
		if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS)
		    //printf("bad-fcs ");
		    hdr->flags_badfcs = true;
		break;
	case IEEE80211_RADIOTAP_ANTENNA:
	    //printf("antenna %d ", u.u8);
	    hdr->has_antenna = true;
	    hdr->antenna = u.u8;
	    break;
	case IEEE80211_RADIOTAP_TSFT:
	    //printf("%" PRIu64 "us tsft ", u.u64);
	    hdr->has_tsft = true;
	    hdr->tsft = u.u64;
	    break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
	    hdr->has_rxflags = true;
	    hdr->rxflags = u.u16;
	    break;
	case IEEE80211_RADIOTAP_TX_FLAGS:
	    hdr->has_txflags = true;
	    hdr->txflags = u.u16;
	    break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	    hdr->has_rts_retries = true;
	    hdr->rts_retries = u.u8;
	    break;
	case IEEE80211_RADIOTAP_DATA_RETRIES:
	    hdr->has_data_retries = true;
	    hdr->data_retries = u.u8;
	    break;
	}
	return 0;
}

void handle_radiotap(const struct timeval& t, WifipcapCallbacks *cbs, const u_char *p, u_int caplen)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)
#define	BIT(n)	(1 << n)
#define	IS_EXTENDED(__p)	\
	    (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

	struct cpack_state cpacker;
	struct ieee80211_radiotap_header *hdr;
	u_int32_t present, next_present;
	u_int32_t *presentp, *last_presentp;
	enum ieee80211_radiotap_type bit;
	int bit0;
	const u_char *iter;
	u_int len;
	int pad;

	u_int length = caplen;

	if (caplen < sizeof(*hdr)) {
	    //printf("[|802.11]");
	    cbs->HandleRadiotap(t, NULL, p, caplen);
	    return;// caplen;
	}

	hdr = (struct ieee80211_radiotap_header *)p;

	len = EXTRACT_LE_16BITS(&hdr->it_len);

	if (caplen < len) {
	    //printf("[|802.11]");
	    cbs->HandleRadiotap(t, NULL, p, caplen);
	    return;// caplen;
	}
	for (last_presentp = &hdr->it_present;
	     IS_EXTENDED(last_presentp) &&
	     (u_char*)(last_presentp + 1) <= p + len;
	     last_presentp++);

	/* are there more bitmap extensions than bytes in header? */
	if (IS_EXTENDED(last_presentp)) {
	    //printf("[|802.11]");
	    cbs->HandleRadiotap(t, NULL, p, caplen);
	    return;// caplen;
	}

	iter = (u_char*)(last_presentp + 1);

	if (cpack_init(&cpacker, (u_int8_t*)iter, len - (iter - p)) != 0) {
	    /* XXX */
	    //printf("[|802.11]");
	    cbs->HandleRadiotap(t, NULL, p, caplen);
	    return;// caplen;
	}

	radiotap_hdr ohdr;
	memset(&ohdr, 0, sizeof(ohdr));
	
	/* Assume no Atheros padding between 802.11 header and body */
	pad = 0;
	for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
	     presentp++, bit0 += 32) {
		for (present = EXTRACT_LE_32BITS(presentp); present;
		     present = next_present) {
			/* clear the least significant bit that is set */
			next_present = present & (present - 1);

			/* extract the least significant bit that is set */
			bit = (enum ieee80211_radiotap_type)
			    (bit0 + BITNO_32(present ^ next_present));

			if (print_radiotap_field(&cpacker, bit, &pad, &ohdr) != 0) {
			    cbs->HandleRadiotap(t, &ohdr, p, caplen);
			    goto out;
			}
		}
	}
	cbs->HandleRadiotap(t, &ohdr, p, caplen);
out:
	handle_80211(t, cbs, p + len, caplen - len);
	//return len + ieee802_11_print(p + len, length - len, caplen - len, pad);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}

///////////////////////////////////////////////////////////////////////////////

Wifipcap::Wifipcap(const char* const *filenames, int nfiles, bool verbose) :
    descr(NULL), verbose(verbose), startTime(TIME_NONE), 
    lastPrintTime(TIME_NONE), packetsProcessed(0)
{
    for (int i=0; i<nfiles; i++) {
	morefiles.push_back(filenames[i]);
    }
    InitNext();
}

Wifipcap::Wifipcap(const char *name, bool live, bool verbose) :
    descr(NULL), verbose(verbose), startTime(TIME_NONE), 
    lastPrintTime(TIME_NONE), packetsProcessed(0)
{
    Init(name, live);
}

bool Wifipcap::InitNext()
{
    if (morefiles.size() < 1)
	return false;
    if (descr)
	pcap_close(descr);
    Init(morefiles.front(), false);
    morefiles.pop_front();
    return true;
}

void Wifipcap::Init(const char *name, bool live) {
    if (verbose)
	cerr << "wifipcap: initializing '" << name << "'" << endl;

    if (!live) {
#ifdef _WIN32
	cerr << "Trace replay is unsupported in windows." << endl;
	exit(1);
#else
	// mini hack: handle gziped files since all our traces are in
	// this format
	int slen = strlen(name);

	bool gzip = !strcmp(name+slen-3, ".gz");
	bool bzip = !strcmp(name+slen-4, ".bz2");
	
	char cmd[256];
	if (gzip)
	    sprintf(cmd, "zcat %s", name);
	else if (bzip)
	    sprintf(cmd, "bzcat %s", name);
	else
	    // using cat here instead of pcap_open or fopen is intentional
	    // neither of these may be able to handle large files (>2GB files)
	    // but cat uses the linux routines to allow it to
	    sprintf(cmd, "cat %s", name);

	FILE *pipe = popen(cmd, "r");
	if (pipe == NULL) {
	    printf("popen(): %s\n", strerror(errno));
	    exit(1);
	}
	descr = pcap_fopen_offline(pipe, errbuf);

        if(descr == NULL) {
            printf("pcap_open_offline(): %s\n", errbuf);
            exit(1);
        }
#endif
    } else {
	descr = pcap_open_live(name,BUFSIZ,1,-1,errbuf);
        if(descr == NULL) {
            printf("pcap_open_live(): %s\n", errbuf);
            exit(1);
        }
    }

    datalink = pcap_datalink(descr);
    if (datalink != DLT_PRISM_HEADER && datalink != DLT_IEEE802_11_RADIO && datalink != DLT_IEEE802_11) {
	if (datalink == DLT_EN10MB) {
	    printf("warning: ethernet datalink type: %s\n",
		   pcap_datalink_val_to_name(datalink));
	} else {
	    printf("warning: unrecognized datalink type: %s\n",
		   pcap_datalink_val_to_name(datalink));
	}
    }
}

Wifipcap::~Wifipcap()
{
    if (descr)
	pcap_close(descr);
}

const char *Wifipcap::SetFilter(const char *filter)
{
    struct bpf_program fp;
    bpf_u_int32 netp;

    if(pcap_compile(descr,&fp,(char *)filter,0,netp) == -1) { 
	return "Error calling pcap_compile"; 
    }
    
    if(pcap_setfilter(descr,&fp) == -1) { 
	return "Error setting filter"; 
    }

    return NULL;
}

void Wifipcap::Run(WifipcapCallbacks *cbs, int maxpkts)
{
    packetsProcessed = 0;
    
    do {
	PcapUserData data;
	data.wcap = this;
	data.cbs = cbs;
	data.header_type = datalink;

	pcap_loop(descr, maxpkts > 0 ? maxpkts - packetsProcessed : 0,
		  handle_packet, reinterpret_cast<u_char *>(&data));
    } while ( InitNext() );
}

///////////////////////////////////////////////////////////////////////////////
