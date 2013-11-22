///////////////////////////////////////////////////////////////////////////////

/* These tcp optinos do not have the size octet */
#define ZEROLENOPT(o) ((o) == TCPOPT_EOL || (o) == TCPOPT_NOP)

#if USING_PARSE_TCP_OPTS
static void parse_tcp_opts(std::list<tcp_opt_t>& opts, const u_char *cp, u_int hlen)
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
#endif



void handle_tcp(WifipcapCallbacks *cbs, 
	   const u_char *bp, u_int length,
	   struct ip4_hdr_t *ip4h, struct ip6_hdr_t *ip6h, int fragmented)
{
    struct tcphdr *tp;
    tp = (struct tcphdr *)bp;
    int hlen;

    // truncated header
    if (length < sizeof(*tp)) {
	cbs->HandleTCP(ip4h, ip6h, NULL, NULL, 0, bp, length);
	return;
    }

    hlen = TH_OFF(tp) * 4;

    // bad header length || missing tcp options
    if (hlen < (int)sizeof(*tp) || length < (int)sizeof(*tp) || hlen > (int)length) {
	cbs->HandleTCP(ip4h, ip6h, NULL, NULL, 0, bp, length);
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

#if USING_PARSE_TCP_OPTS
    parse_tcp_opts(hdr.opts, bp+sizeof(*tp), hlen-sizeof(*tp));
#endif

    cbs->HandleTCP(ip4h, ip6h, &hdr,
                   hlen==sizeof(*tp)?NULL:bp+sizeof(*tp), hlen-sizeof(*tp), bp+hlen, length-hlen);
}

void handle_udp( WifipcapCallbacks *cbs, 
	   const u_char *bp, u_int length,
	   struct ip4_hdr_t *ip4h, struct ip6_hdr_t *ip6h, int fragmented)
{
    struct udphdr *uh;
    uh = (struct udphdr *)bp;

    if (length < sizeof(struct udphdr)) {
	// truncated udp header
	cbs->HandleUDP(ip4h, ip6h, NULL, bp, length);
	return;
    }

    udp_hdr_t hdr;
    hdr.sport = EXTRACT_16BITS(&uh->uh_sport);
    hdr.dport = EXTRACT_16BITS(&uh->uh_dport);
    hdr.len   = EXTRACT_16BITS(&uh->uh_ulen);
    hdr.cksum = EXTRACT_16BITS(&uh->uh_sum);

    cbs->HandleUDP(ip4h, ip6h, &hdr, bp+sizeof(struct udphdr), length-sizeof(struct udphdr));
}

void handle_icmp( WifipcapCallbacks *cbs, 
	    const u_char *bp, u_int length,
	    struct ip4_hdr_t *ip4h, struct ip6_hdr_t *ip6h, int fragmented)
{
    struct icmp *dp;
    dp = (struct icmp *)bp;

    if (length < 4) {
	// truncated icmp header
	cbs->HandleICMP(ip4h, ip6h, -1, -1, bp, length);
	return;
    }

    cbs->HandleICMP(ip4h, ip6h, dp->icmp_type, dp->icmp_code, bp+4, length-4);
}

///////////////////////////////////////////////////////////////////////////////

struct ip_print_demux_state {
    struct ip *ip;
    const u_char *cp;
    u_int   len, off;
    u_char  nh;
    int     advance;
};

void ip_demux( WifipcapCallbacks *cbs, ip4_hdr_t *hdr,
                                  struct ip_print_demux_state *ipds, u_int len)
{
    //struct protoent *proto;

//again:
    switch (ipds->nh) {
    case IPPROTO_TCP:
        /* pass on the MF bit plus the offset to detect fragments */
        handle_tcp(cbs, ipds->cp, ipds->len, hdr, NULL,
                   ipds->off & (IP_MF|IP_OFFMASK));
        break;
		
    case IPPROTO_UDP:
        /* pass on the MF bit plus the offset to detect fragments */
        handle_udp(cbs, ipds->cp, ipds->len, hdr, NULL,
                   ipds->off & (IP_MF|IP_OFFMASK));
        break;
		
    case IPPROTO_ICMP:
        /* pass on the MF bit plus the offset to detect fragments */
        handle_icmp(cbs, ipds->cp, ipds->len, hdr, NULL,
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
        cbs->HandleL3Unknown(hdr, NULL, ipds->cp, ipds->len);
	    
        break;
    }
}

void handle_ip6( WifipcapCallbacks *cbs, const u_char *ptr, u_int len);
void handle_ip( WifipcapCallbacks *cbs, const u_char *ptr, u_int len)
{
    struct ip_print_demux_state  ipd;
    struct ip_print_demux_state *ipds=&ipd;
    u_int hlen;

    // truncated (in fact, nothing!)
    if (len == 0) {
	cbs->HandleIP(NULL, NULL, 0, ptr, len);
	return;
    }

    ipds->ip = (struct ip *)ptr;
    if (IP_V(ipds->ip) != 4) {
	if (IP_V(ipds->ip) == 6) {
	    // wrong link-layer encap!
	    handle_ip6(cbs, ptr, len);
	    return;
	}
    }
    if (len < sizeof (struct ip)) {
	// truncated!
	cbs->HandleIP(NULL, NULL, 0, ptr, len);
	return;
    }
    hlen = IP_HL(ipds->ip) * 4;
    ipds->len = EXTRACT_16BITS(&ipds->ip->ip_len);
    if (len < ipds->len) {
	// truncated IP
	// this is ok, we'll just report the truncation later
    }
    if (ipds->len < hlen) {
	// missing some ip options!
	cbs->HandleIP(NULL, NULL, 0, ptr, len);
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

    cbs->HandleIP(&hdr, hlen==sizeof(struct ip)?NULL:ptr+sizeof(struct ip), hlen-sizeof(struct ip), ptr+hlen, len-hlen);
    
    /*
     * If this is fragment zero, hand it to the next higher
     * level protocol.
     */
    if ((ipds->off & 0x1fff) == 0) {
	ipds->cp = (const u_char *)ipds->ip + hlen;
	ipds->nh = ipds->ip->ip_p;
	
	ip_demux(cbs, &hdr, ipds, len);
    } else {
	// This is a fragment of a previous packet. can't demux it
	return;
    }
}

void handle_ip6( WifipcapCallbacks *cbs, const u_char *ptr, u_int len)
{
    const struct ip6_hdr *ip6;
    if (len < sizeof (struct ip6_hdr)) {
	cbs->HandleIP6(NULL, ptr, len);
	return;
    }
    ip6 = ( const struct ip6_hdr *)ptr;

    ip6_hdr_t hdr;
    memcpy(&hdr, ip6, sizeof(hdr));
    hdr.ip6_plen = EXTRACT_16BITS(&ip6->ip6_plen);
    hdr.ip6_flow = EXTRACT_32BITS(&ip6->ip6_flow);

    cbs->HandleIP6(&hdr, ptr+sizeof(hdr), len-sizeof(hdr));

    int nh = ip6->ip6_nxt;
    switch(nh) {
    case IPPROTO_TCP:
	handle_tcp(cbs, ptr+sizeof(ip6_hdr), len-sizeof(ip6_hdr), 
		   NULL, &hdr, 0);
	break;
    case IPPROTO_UDP:
	handle_udp(cbs, ptr+sizeof(ip6_hdr), len-sizeof(ip6_hdr), 
		   NULL, &hdr, 0);
	break;
    default:
	cbs->HandleL3Unknown(NULL, &hdr, 
			     ptr+sizeof(ip6_hdr), len-sizeof(ip6_hdr));
	break;
    }
}

void handle_arp( WifipcapCallbacks *cbs, const u_char *ptr, u_int len)
{
    struct arp_pkthdr *ap;
    //u_short pro, hrd, op;

    if (len < sizeof(struct arp_pkthdr)) {
	cbs->HandleARP(NULL, ptr, len);
	return;
    }

    ap = (struct arp_pkthdr *)ptr;
    cbs->HandleARP(ap, ptr+ARP_HDRLEN, len-ARP_HDRLEN);
}

