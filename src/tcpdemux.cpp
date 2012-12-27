/**
 * 
 * tcpdemux.cpp
 * A tcpip demultiplier.
 *
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"

#include <iostream>
#include <sstream>
#include <vector>



/* static */ int tcpdemux::max_stored_flows = 100;

tcpdemux::tcpdemux():outdir("."),flow_counter(0),packet_counter(0),
		     xreport(0),max_fds(10),flow_map(),openflows(),stored_flow_map(),
		     stored_flows(),start_new_connections(false),opt(),fs()
		     
{
    /* Find out how many files we can have open safely...subtract 4 for
     * stdin, stdout, stderr, and the packet filter; one for breathing
     * room (we open new files before closing old ones), and one more to
     * be safe.
     */
    max_fds = get_max_fds() - NUM_RESERVED_FDS;
}

/* static */ tcpdemux *tcpdemux::getInstance()
{
    static tcpdemux * theInstance = 0;
    if(theInstance==0) theInstance = new tcpdemux();
    return theInstance;
}



/**
 * Implement a list of openflows, each with an associated file descriptor.
 * When a new file needs to be opened, we can close a flow if necessary.
 */
void tcpdemux::close_all_fd()
{
    for(tcpset::iterator it = openflows.begin();it!=openflows.end();it++){
	(*it)->close_file();
    }
    openflows.clear();
}


void tcpdemux::close_tcpip_fd(tcpip *i)
{
    i->close_file();
    openflows.erase(i);
}

/**
 * find the flow that has been written to in the furthest past and close it.
 */
void tcpdemux::close_oldest_fd()
{
    tcpip *oldest_tcp=0;
    for(tcpset::iterator it = openflows.begin();it!=openflows.end();it++){
	if(oldest_tcp==0 || (*it)->last_packet_number < oldest_tcp->last_packet_number){
	    oldest_tcp = (*it);
	}
    }
    if(oldest_tcp) close_tcpip_fd(oldest_tcp);
}

/* Open a file, closing one of the existing flows f necessary.
 */
int tcpdemux::retrying_open(const std::string &filename,int oflag,int mask)
{
    while(true){
	if(openflows.size() >= max_fds) close_oldest_fd();
	int fd = ::open(filename.c_str(),oflag,mask);
	DEBUG(2)("::open(%s,%d,%d)=%d",filename.c_str(),oflag,mask,fd);
	if(fd>=0) return fd;
	DEBUG(2)("retrying_open ::open failed with errno=%d",errno);
	if (errno != ENFILE && errno != EMFILE){
	    DEBUG(2)("retrying_open ::open failed with errno=%d (%s)",errno,strerror(errno));
	    return -1;		// wonder what it was
	}
	DEBUG(5) ("too many open files -- contracting FD ring (size=%d)", (int)openflows.size());
	close_oldest_fd();
    }
}

/* Find previously a previously created flow state in the database.
 */
tcpip *tcpdemux::find_tcpip(const flow_addr &flow)
{
    flow_map_t::const_iterator it = flow_map.find(flow);
    if (it==flow_map.end()){
	return NULL; // flow not found
    }
    return it->second;
}

/* Create a new flow state structure for a given flow.
 * Puts the flow in the map.
 * Returns a pointer to the new state.
 *
 * This is called by process_tcp
 *
 * NOTE: We keep pointers to tcp structures in the map, rather than
 * the structures themselves. This makes the map slightly more efficient,
 * since it doesn't need to shuffle entire structures.
 */

tcpip *tcpdemux::create_tcpip(const flow_addr &flowa, int32_t vlan,tcp_seq isn,const timeval &ts)
{
    /* create space for the new state */
    flow flow(flowa,vlan,ts,ts,flow_counter++);

    tcpip *new_tcpip = new tcpip(*this,flow,isn);
    new_tcpip->last_packet_number = packet_counter++;
    new_tcpip->nsn   = isn+1;		// expected
    DEBUG(5) ("%s: new flow. next seq num (nsn):%d", new_tcpip->flow_pathname.c_str(),new_tcpip->nsn);
    flow_map[flow] = new_tcpip;
    return new_tcpip;
}

/**
 * remove a flow from the database and close the flow
 */

void tcpdemux::remove_flow(const flow_addr &flow)
{
    flow_map_t::iterator it = flow_map.find(flow);
    if(it!=flow_map.end()){
	close_tcpip_fd(it->second);
	delete it->second;
	flow_map.erase(it);
    }
}

void tcpdemux::remove_all_flows()
{
    for(flow_map_t::iterator it=flow_map.begin();it!=flow_map.end();it++){
	delete it->second;
    }
    flow_map.clear();
}

/****************************************************************
 *** tcpdemultiplexer 
 ****************************************************************/

/* Try to find the maximum number of FDs this system can have open */
unsigned int tcpdemux::get_max_fds(void)
{
    int max_descs = 0;
    const char *method=0;

    /* Use OPEN_MAX if it is available */
#if defined (OPEN_MAX)
    method = "OPEN_MAX";
    max_descs = OPEN_MAX;
#elif defined(RLIMIT_NOFILE)
    {
	struct rlimit limit;
	memset(&limit,0,sizeof(limit));

	method = "rlimit";
	if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
	    perror("getrlimit");
	    exit(1);
	}

	/* set the current to the maximum or specified value */
	if (max_desired_fds) limit.rlim_cur = max_desired_fds;
	else limit.rlim_cur = limit.rlim_max;

	if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
	    perror("setrlimit");
	    exit(1);
	}
	max_descs = limit.rlim_max;

#ifdef RLIM_INFINITY
	if (limit.rlim_max == RLIM_INFINITY) max_descs = MAX_FD_GUESS * 4;	/* pick a more reasonable max */
#endif
    }
#elif defined (_SC_OPEN_MAX)
    /* Okay, you don't have getrlimit() and you don't have OPEN_MAX.
     * Time to try the POSIX sysconf() function.  (See Stevens'
     * _Advanced Programming in the UNIX Environment_).  */
    method = "POSIX sysconf";
    errno = 0;
    if ((max_descs = sysconf(_SC_OPEN_MAX)) < 0) {
	if (errno == 0)
	    max_descs = MAX_FD_GUESS * 4;
	else {
	    perror("calling sysconf");
	    exit(1);
	}
    }

    /* if everything has failed, we'll just take a guess */
#else
    method = "MAX_FD_GUESS";
    max_descs = MAX_FD_GUESS;
#endif
    /* this must go here, after rlimit code */
    if (opt.max_desired_fds) {
	DEBUG(10) ("using only %d FDs", opt.max_desired_fds);
	return opt.max_desired_fds;
    }

    DEBUG(10) ("found max FDs to be %d using %s", max_descs, method);
    return max_descs;
}


/*
 * Called to processes a tcp packet
 * 
 * creates a new tcp connection if necessary, then asks the connection to either
 * print the packet or store it.
 */

#pragma GCC diagnostic ignored "-Wcast-align"
void tcpdemux::process_tcp(const struct timeval &ts,const u_char *data, uint32_t length,
			const ipaddr &src, const ipaddr &dst,int32_t vlan,sa_family_t family)
{
    if (length < sizeof(struct tcphdr)) {
	DEBUG(6) ("received truncated TCP segment!");
	return;
    }

    struct tcphdr *tcp_header = (struct tcphdr *) data;

    /* calculate the total length of the TCP header including options */
    u_int tcp_header_len = tcp_header->th_off * 4;

    /* fill in the flow_addr structure with info that identifies this flow */
    flow_addr this_flow(src,dst,ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport),family);

    tcp_seq seq  = ntohl(tcp_header->th_seq);
    bool syn_set = IS_SET(tcp_header->th_flags, TH_SYN);
    bool ack_set = IS_SET(tcp_header->th_flags, TH_ACK);
    bool fin_set = IS_SET(tcp_header->th_flags, TH_FIN);

    /* recalculate the beginning of data and its length, moving past the
     * TCP header
     */
    data   += tcp_header_len;
    length -= tcp_header_len;

    /* see if we have state about this flow; if not, create it */
    int32_t  delta = 0;			// from current position in tcp connection; must be SIGNED 32 bit!
    tcpip   *tcp = find_tcpip(this_flow);
    
    /* If this_flow is not in the database and the start_new_connections flag is false, just return */
    if(tcp==0 && start_new_connections==false) return; 

    /* flow is in the database; find it */
    if(tcp){
	/* Compute delta based on next expected sequence number.
	 * If delta will be too much, start a new flow.
         *
         * Gosh, I hope we don't get a packet from the old flow when
         * we are processing the new one. Perhaps we should be able to have
         * multiple flows at the same time with the same quad, and they are
         * at different window areas...
         * 
	 */
	delta = seq - tcp->nsn;		// notice that signed offset is calculated

	if(abs(delta) > opt.max_seek){
	    remove_flow(this_flow);
	    tcp = 0;
	}
    }

    /* At this point, tcp may be NULL because:
     * case 1 - It's a new connection and SYN IS SET; normal case
     * case 2 - Extra packets on a now-closed connection
     * case 3 - Packets for which the initial part of the connection was missed
     * case 4 - It's a connecton that had a huge gap and was expired out of the databsae
     *
     * THIS IS THE ONLY PLACE THAT create_tcpip() is called.
     */

    /* q: what if syn is set AND there is data? */
    /* q: what if syn is set AND we already know about this connection? */

    if (tcp==NULL){

        /* Don't process if this is not a SYN and there is no data. */
        if(syn_set==false && length==0) return;

	/* Create a new connection.
	 * delta will be 0, because it's a new connection!
	 */
	tcp_seq isn = syn_set ? seq : seq-1;
	tcp = create_tcpip(this_flow, vlan, isn, ts);
    }

    /* Now tcp is valid */
    tcp->myflow.tlast = ts;		// most recently seen packet
    tcp->myflow.packet_count++;

    /*
     * 2012-10-24 slg - the first byte is sent at SEQ==ISN+1.
     * The first byte in POSIX files have an LSEEK of 0.
     * The original code overcame this issue by introducing an intentional off-by-one
     * error with the statement tcp->isn++.
     * 
     * With the new TCP state-machine we simply follow the spec.
     *
     * The new state machine works by examining the SYN and ACK packets
     * in accordance with the TCP spec.
     */
    if(syn_set){
	if(tcp->syn_count>1){
	    DEBUG(1)("Multiple SYNs (%d) seen on a single connection.",tcp->syn_count);
	}
	tcp->syn_count++;
	if( !ack_set ){
	    DEBUG(50) ("packet is handshake SYN"); /* First packet of three-way handshake */
	    tcp->dir = tcpip::dir_cs;	// client->server
	} else {
	    DEBUG(50) ("packet is handshake SYN/ACK"); /* second packet of three-way handshake  */
	    tcp->dir = tcpip::dir_sc;	// server->client
	}
	if(length>0){
	    tcp->violations++;
	    DEBUG(1) ("TCP PROTOCOL VIOLATION: SYN with data! (length=%d)",length);
	}
    }
    if(length==0) DEBUG(50) ("got TCP segment with no data"); // seems pointless to notify

    /* process any data.
     * Notice that this typically won't be called for the SYN or SYN/ACK,
     * since they both have no data by definition.
     */
    if (length>0){
	if (opt.console_output) {
	    tcp->print_packet(data, length);
	} else {
	    if (opt.store_output){
		tcp->store_packet(data, length, delta);
	    }
	}
    }

    /* Count the FINs.
     * If this is a fin, determine the size of the stream
     */
    if (fin_set){
        tcp->fin_count++;
        if(tcp->fin_count==1){
            tcp->fin_size = (seq+length-tcp->isn)-1;
        }
    }

    /* If a fin was sent and we've seen all of the bytes, close the stream */
    DEBUG(50)("%d>0 && %d == %d",tcp->fin_count,tcp->seen_bytes(),tcp->fin_size);
    if (tcp->fin_count>0 && tcp->seen_bytes() == tcp->fin_size){
        DEBUG(50)("all bytes have been received; closing connection");
        remove_flow(this_flow);	// take it out of the map  // BUG??
    }
    DEBUG(50)("fin_set=%d  seq=%u fin_count=%d  seq_count=%d len=%d isn=%u",
            fin_set,seq,tcp->fin_count,tcp->syn_count,length,tcp->isn);
}
#pragma GCC diagnostic warning "-Wcast-align"


/* This is called when we receive an IPv4 datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
#pragma GCC diagnostic ignored "-Wcast-align"
void tcpdemux::process_ip4(const struct timeval &ts,const u_char *data, uint32_t caplen,int32_t vlan)
{
    const struct ip *ip_header = (struct ip *) data;
    u_int ip_header_len;
    u_int ip_total_len;

    /* make sure that the packet is at least as long as the min IP header */
    if (caplen < sizeof(struct ip)) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    DEBUG(100)("process_ip4. caplen=%d vlan=%d  ip_p=%d",(int)caplen,(int)vlan,(int)ip_header->ip_p);
    if(debug>200){
	sbuf_t sbuf(pos0_t(),(const uint8_t *)data,caplen,caplen,false);
	sbuf.hex_dump(std::cerr);
    }

    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip_p != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip_p);
	return;
    }

    /* check and see if we got everything.  NOTE: we must use
     * ip_total_len after this, because we may have captured bytes
     * beyond the end of the packet (e.g. ethernet padding).
     */
    ip_total_len = ntohs(ip_header->ip_len);
    if (caplen < ip_total_len) {
	DEBUG(6) ("warning: captured only %ld bytes of %ld-byte IP datagram",
		  (long) caplen, (long) ip_total_len);
    }

    /* XXX - throw away everything but fragment 0; this version doesn't
     * know how to do fragment reassembly.
     */
    if (ntohs(ip_header->ip_off) & 0x1fff) {
	DEBUG(2) ("warning: throwing away IP fragment from X to X");
	return;
    }

    /* figure out where the IP header ends */
    ip_header_len = ip_header->ip_hl * 4;

    /* make sure there's some data */
    if (ip_header_len > ip_total_len) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* do TCP processing, faking an ipv6 address  */
    process_tcp(ts,data + ip_header_len, ip_total_len - ip_header_len,
		ipaddr(ip_header->ip_src.s_addr),
		ipaddr(ip_header->ip_dst.s_addr),
		vlan,AF_INET);
}
#pragma GCC diagnostic warning "-Wcast-align"


/* This is called when we receive an IPv6 datagram.
 *
 * Note: we don't support IPv6 extended headers
 */

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

/* These might be defined from an include file, so undef them to be sure */
#undef ip6_vfc
#undef ip6_flow
#undef ip6_plen	
#undef ip6_nxt	
#undef ip6_hlim	
#undef ip6_hops	

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

void tcpdemux::process_ip6(const struct timeval &ts,const u_char *data, const uint32_t caplen, const int32_t vlan)
{
    const struct private_ip6_hdr *ip_header = (struct private_ip6_hdr *) data;
    u_int16_t ip_payload_len;

    /* make sure that the packet is at least as long as the IPv6 header */
    if (caplen < sizeof(struct private_ip6_hdr)) {
	DEBUG(6) ("received truncated IPv6 datagram!");
	return;
    }


    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip6_nxt != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip6_nxt);
	return;
    }

    ip_payload_len = ntohs(ip_header->ip6_plen);

    /* make sure there's some data */
    if (ip_payload_len == 0) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* do TCP processing */

    process_tcp(ts,
		data + sizeof(struct private_ip6_hdr),
		ip_payload_len,
		ipaddr(ip_header->ip6_src.s6_addr),
		ipaddr(ip_header->ip6_dst.s6_addr),
		vlan,AF_INET6);
}



/* This is called when we receive an IPv4 or IPv6 datagram.
 * This function calls process_ip4 or process_ip6
 */

#pragma GCC diagnostic ignored "-Wcast-align"
void tcpdemux::process_ip(const struct timeval &ts,const u_char *data, uint32_t caplen,int32_t vlan)
{
    const struct ip *ip_header = (struct ip *) data;
    if (caplen < sizeof(struct ip)) {
	DEBUG(6) ("can't determine IP datagram version!");
	return;
    }

    if(ip_header->ip_v == 6) {
	process_ip6(ts,data, caplen,vlan);
    } else {
	process_ip4(ts,data, caplen,vlan);
    }
}
#pragma GCC diagnostic warning "-Wcast-align"
 
 
