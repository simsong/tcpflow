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



/* static */ uint32_t tcpdemux::max_saved_flows = 100;

tcpdemux::tcpdemux():outdir("."),flow_counter(0),packet_counter(0),
		     xreport(0),pwriter(0),max_open_flows(),max_fds(get_max_fds()-NUM_RESERVED_FDS),
                     flow_map(),open_flows(),saved_flow_map(),
		     saved_flows(),start_new_connections(false),opt(),fs()
		     
{
}

/* static */ tcpdemux *tcpdemux::getInstance()
{
    static tcpdemux * theInstance = 0;
    if(theInstance==0) theInstance = new tcpdemux();
    return theInstance;
}



/**
 * Implement a list of open_flows, each with an associated file descriptor.
 * When a new file needs to be opened, we can close a flow if necessary.
 */
void tcpdemux::close_all_fd()
{
    tcpset open_flows_copy(open_flows);	// make a copy because we're going to modify it

    for(tcpset::const_iterator it = open_flows_copy.begin();it!=open_flows_copy.end();it++){
	(*it)->close_file();
    }
    assert(open_flows.size()==0);	// we've closed them all
}


/**
 * find the flow that has been written to in the furthest past and close it.
 */
void tcpdemux::close_oldest_fd()
{
    tcpip *oldest_tcp=0;
    for(tcpset::iterator it = open_flows.begin();it!=open_flows.end();it++){
	if(oldest_tcp==0 || (*it)->last_packet_number < oldest_tcp->last_packet_number){
	    oldest_tcp = (*it);
	}
    }
    if(oldest_tcp) oldest_tcp->close_file();
}

/* Open a file, closing one of the existing flows f necessary.
 */
int tcpdemux::retrying_open(const std::string &filename,int oflag,int mask)
{
    while(true){
	if(open_flows.size() >= max_fds) close_oldest_fd();
	int fd = ::open(filename.c_str(),oflag,mask);
	DEBUG(2)("retrying_open ::open(fn=%s,oflag=x%x,mask:x%x)=%d",filename.c_str(),oflag,mask,fd);
	if(fd>=0){
            /* Open was successful */
            return fd;
        }
	DEBUG(2)("retrying_open ::open failed with errno=%d",errno);
	if (errno != ENFILE && errno != EMFILE){
	    DEBUG(2)("retrying_open ::open failed with errno=%d (%s)",errno,strerror(errno));
	    return -1;		// wonder what it was
	}
	DEBUG(5) ("too many open files -- contracting FD ring (size=%d)", (int)open_flows.size());
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
 * This is called by tcpdemux::process_tcp(). (Only place it is called)
 *
 * @param - pi - first packet seen on this connection.
 *
 * NOTE: We keep pointers to tcp structures in the map, rather than
 * the structures themselves. This makes the map slightly more efficient,
 * since it doesn't need to shuffle entire structures.
 *
 *
 * TK: Note that the flow() is created on the stack and then used in new tcpip().
 * This is resulting in an unnecessary copy. 
 */

tcpip *tcpdemux::create_tcpip(const flow_addr &flowa, be13::tcp_seq isn,const be13::packet_info &pi)
{
    /* create space for the new state */
    flow flow(flowa,flow_counter++,pi);

    tcpip *new_tcpip = new tcpip(*this,flow,isn);
    new_tcpip->last_packet_number = packet_counter++;
    new_tcpip->nsn   = isn+1;		// expected sequence number of the first byte
    DEBUG(5) ("%s: new flow. next seq num (nsn):%d", new_tcpip->flow_pathname.c_str(),new_tcpip->nsn);
    flow_map[flow] = new_tcpip;
    return new_tcpip;
}

/**
 * remove a flow from the database and close the flow
 * These are the only places where a tcpip object is deleted.
 */

void tcpdemux::post_process(tcpip *tcp)
{
    std::stringstream xmladd;		// for this <fileobject>
    if(opt.post_processing && tcp->file_created && tcp->last_byte>0){
        /** 
         * After the flow is finished, put it in an SBUF and process it.
         * if we are doing post-processing.
         * This is called from tcpip::~tcpip() in tcpip.cpp.
         */

        /* Open the fd if it is not already open */
        tcp->open_file();
        if(tcp->fd>=0){
            sbuf_t *sbuf = sbuf_t::map_file(tcp->flow_pathname,pos0_t(tcp->flow_pathname),tcp->fd);
            if(sbuf){
                process_sbuf(scanner_params(scanner_params::scan,*sbuf,*(fs),&xmladd));
                delete sbuf;
                sbuf = 0;
            }
        }
    }
    tcp->close_file();
    if(xreport) tcp->dump_xml(xreport,xmladd.str());
    /**
     * Before we delete the tcp structure, save information about the saved flow
     */
    saved_flow_remove_oldest_if_necessary();
    save_flow(tcp);
    delete tcp;
}

void tcpdemux::remove_flow(const flow_addr &flow)
{
    flow_map_t::iterator it = flow_map.find(flow);
    if(it!=flow_map.end()){
        post_process(it->second);
	flow_map.erase(it);
    }
}

void tcpdemux::remove_all_flows()
{
    for(flow_map_t::iterator it=flow_map.begin();it!=flow_map.end();it++){
        post_process(it->second);
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

    /* No longer users OPEN_MAX */
#if defined (HAVE_GETDTABLESIZE)
    method = "getdtablesize";
    max_descs = getdtablesize();
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
	limit.rlim_cur = limit.rlim_max;

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
    DEBUG(10) ("found max FDs to be %d using %s", max_descs, method);
    return max_descs;
}


/*
 * open the packet save flow
 */
void tcpdemux::save_unk_packets(const std::string &ofname,const std::string &ifname)
{
    pwriter = pcap_writer::open_copy(ofname,ifname);
}

/**
 * save information on this flow needed to handle strangling packets
 */
void tcpdemux::save_flow(tcpip *tcp)
{
    saved_flow *sf = new saved_flow(tcp);
    saved_flow_map[*sf] = sf;
    saved_flows.push_back(sf);
}

void tcpdemux::saved_flow_remove_oldest_if_necessary()
{
    if(saved_flows.size()>0 && saved_flows.size()>max_saved_flows){
        flow_addr this_flow = *saved_flows.at(0);
        saved_flow_map.erase(this_flow);
        saved_flows.erase(saved_flows.begin());
    }
}

/**
 * process_tcp():
 *
 * Called to processes a tcp packet from either process_ip4() or process_ip6().
 * The caller breaks out the ip addresses and finds the start of the tcp header.
 *
 * Skips but otherwise ignores TCP options.
 * 
 * creates a new tcp connection if necessary, then asks the connection to either
 * print the packet or store it.
 */

#define IS_SET(vector, flag) ((vector) & (flag))

#pragma GCC diagnostic ignored "-Wcast-align"
#include "iptree.h"
iptree mytree;
ip2tree my2tree;

int tcpdemux::process_tcp(const ipaddr &src, const ipaddr &dst,sa_family_t family,
                          const u_char *tcp_data, uint32_t tcp_datalen,
                          const be13::packet_info &pi)
{
    if(iphtest==1){                     // mode 1 testing - when the tree gets 4000, drop it to 400
        mytree.add(src.addr,family==AF_INET6 ? 16 : 4,1 );
        mytree.add(dst.addr,family==AF_INET6 ? 16 : 4,1);
        my2tree.add_pair(src.addr,dst.addr,family==AF_INET6 ? 16 : 4,1);
    }

    if (tcp_datalen < sizeof(struct be13::tcphdr)) {
	DEBUG(6) ("received truncated TCP segment! (%u<%u)",
                  (u_int)tcp_datalen,(u_int)sizeof(struct be13::tcphdr));
	return 0;
    }

    struct be13::tcphdr *tcp_header = (struct be13::tcphdr *) tcp_data;

    /* calculate the total length of the TCP header including options */
    u_int tcp_header_len = tcp_header->th_off * 4;

    /* fill in the flow_addr structure with info that identifies this flow */
    flow_addr this_flow(src,dst,ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport),family);

    be13::tcp_seq seq  = ntohl(tcp_header->th_seq);
    bool syn_set = IS_SET(tcp_header->th_flags, TH_SYN);
    bool ack_set = IS_SET(tcp_header->th_flags, TH_ACK);
    bool fin_set = IS_SET(tcp_header->th_flags, TH_FIN);

    /* recalculate the beginning of data and its length, moving past the
     * TCP header
     */
    tcp_data   += tcp_header_len;
    tcp_datalen -= tcp_header_len;

    /* see if we have state about this flow; if not, create it */
    int32_t  delta = 0;			// from current position in tcp connection; must be SIGNED 32 bit!
    tcpip   *tcp = find_tcpip(this_flow);
    
    /* If this_flow is not in the database and the start_new_connections flag is false, just return */
    if(tcp==0 && start_new_connections==false) return 0; 

    if(tcp==0){
        if(tcp_datalen==0){                       // zero length packet
            if(fin_set) return 0;              // FIN on a connection that's unknown; safe to ignore
            if(syn_set==false && ack_set==false) return 0; // neither a SYN nor ACK; return
        } else {
            /* Data present on a flow that is not actively being demultiplexed.
             * See if it is a saved flow. If so, see if the data in the packet
             * matches what is on the disk. If so, return.
             *
             */
            saved_flow_map_t::const_iterator it = saved_flow_map.find(this_flow);
            if(it!=saved_flow_map.end()){
                uint32_t offset = seq - it->second->isn - 1;
                bool data_match = false;
                int fd = open(it->second->saved_filename.c_str(),O_RDONLY | O_BINARY);
                if(fd>0){
                    char *buf = (char *)malloc(tcp_datalen);
                    if(buf){
                        DEBUG(100)("lseek(fd,%"PRId64",SEEK_SET)",(int64_t)(offset));
                        lseek(fd,offset,SEEK_SET);
                        ssize_t r = read(fd,buf,tcp_datalen);
                        data_match = (r==(ssize_t)tcp_datalen) && memcmp(buf,tcp_data,tcp_datalen)==0;
                        free(buf);
                    }
                    close(fd);
                }
                DEBUG(60)("Packet matches saved flow. offset=%u len=%d filename=%s data match=%d\n",
                          offset,tcp_datalen,it->second->saved_filename.c_str(),data_match);
                if(data_match) return 0;
            }
        }
    }

    /* flow is in the database; make sure the gap isn't too big.*/
    if(tcp){
	/* Compute delta based on next expected sequence number.
	 * If delta will be too much, start a new flow.
         *
         * NOTE: I hope we don't get a packet from the old flow when
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
        if(syn_set==false && tcp_datalen==0) return 0;

	/* Create a new connection.
	 * delta will be 0, because it's a new connection!
	 */
        be13::tcp_seq isn = syn_set ? seq : seq-1;
	tcp = create_tcpip(this_flow, isn, pi);
    }

    /* Now tcp is valid */
    tcp->myflow.tlast = pi.ts;		// most recently seen packet
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
	    DEBUG(2)("Multiple SYNs (%d) seen on connection %s",tcp->syn_count,tcp->flow_pathname.c_str());
	}
	tcp->syn_count++;
	if( !ack_set ){
	    DEBUG(50) ("packet is handshake SYN"); /* First packet of three-way handshake */
	    tcp->dir = tcpip::dir_cs;	// client->server
	} else {
	    DEBUG(50) ("packet is handshake SYN/ACK"); /* second packet of three-way handshake  */
	    tcp->dir = tcpip::dir_sc;	// server->client
	}
	if(tcp_datalen>0){
	    tcp->violations++;
	    DEBUG(1) ("TCP PROTOCOL VIOLATION: SYN with data! (length=%d)",tcp_datalen);
	}
    }
    if(tcp_datalen==0) DEBUG(50) ("got TCP segment with no data"); // seems pointless to notify

    /* process any data.
     * Notice that this typically won't be called for the SYN or SYN/ACK,
     * since they both have no data by definition.
     */
    if (tcp_datalen>0){
	if (opt.console_output) {
	    tcp->print_packet(tcp_data, tcp_datalen);
	} else {
	    if (opt.store_output){
		tcp->store_packet(tcp_data, tcp_datalen, delta);
	    }
	}
    }

    /* Count the FINs.
     * If this is a fin, determine the size of the stream
     */
    if (fin_set){
        tcp->fin_count++;
        if(tcp->fin_count==1){
            tcp->fin_size = (seq+tcp_datalen-tcp->isn)-1;
        }
    }

    /* If a fin was sent and we've seen all of the bytes, close the stream */
    DEBUG(50)("%d>0 && %d == %d",tcp->fin_count,tcp->seen_bytes(),tcp->fin_size);
    if (tcp->fin_count>0 && tcp->seen_bytes() == tcp->fin_size){
        DEBUG(50)("all bytes have been received; removing flow");
        remove_flow(this_flow);	// take it out of the map  
    }
    DEBUG(50)("fin_set=%d  seq=%u fin_count=%d  seq_count=%d len=%d isn=%u",
            fin_set,seq,tcp->fin_count,tcp->syn_count,tcp_datalen,tcp->isn);
    return 0;                           // successfully processed
}
#pragma GCC diagnostic warning "-Wcast-align"


/* This is called when we receive an IPv4 datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
#pragma GCC diagnostic ignored "-Wcast-align"



int tcpdemux::process_ip4(const be13::packet_info &pi)
{
    /* make sure that the packet is at least as long as the min IP header */
    if (pi.ip_datalen < sizeof(struct be13::ip4)) {
	DEBUG(6) ("received truncated IP datagram!");
	return -1;                      // couldn't process
    }

    const struct be13::ip4 *ip_header = (struct be13::ip4 *) pi.ip_data;
    u_int ip_header_len;
    u_int ip_total_len;

    DEBUG(100)("process_ip4. caplen=%d vlan=%d  ip_p=%d",(int)pi.pcap_hdr->caplen,(int)pi.vlan(),(int)ip_header->ip_p);
    if(debug>200){
	sbuf_t sbuf(pos0_t(),(const uint8_t *)pi.ip_data,pi.ip_datalen,pi.ip_datalen,false);
	sbuf.hex_dump(std::cerr);
    }

    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip_p != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip_p);
	return -1;                      // couldn't process
    }

    /* check and see if we got everything.  NOTE: we must use
     * ip_total_len after this, because we may have captured bytes
     * beyond the end of the packet (e.g. ethernet padding).
     */
    ip_total_len = ntohs(ip_header->ip_len);
    if (pi.ip_datalen < ip_total_len) {
	DEBUG(6) ("warning: captured only %ld bytes of %ld-byte IP datagram",
		  (long) pi.ip_datalen, (long) ip_total_len);
    }

    /* XXX - throw away everything but fragment 0; this version doesn't
     * know how to do fragment reassembly.
     */
    if (ntohs(ip_header->ip_off) & 0x1fff) {
	DEBUG(2) ("warning: throwing away IP fragment from X to X");
	return -1;
    }

    /* figure out where the IP header ends */
    ip_header_len = ip_header->ip_hl * 4;

    /* make sure there's some data */
    if (ip_header_len > ip_total_len) {
	DEBUG(6) ("received truncated IP datagram!");
	return -1;
    }

    /* do TCP processing, faking an ipv6 address  */
    uint16_t ip_payload_len = ip_total_len - ip_header_len;
    ipaddr src(ip_header->ip_src.addr);
    ipaddr dst(ip_header->ip_dst.addr);
    return process_tcp(src, dst, AF_INET,
                       pi.ip_data + ip_header_len, ip_payload_len,
                       pi);
}
#pragma GCC diagnostic warning "-Wcast-align"


/* This is called when we receive an IPv6 datagram.
 *
 * Note: we don't support IPv6 extended headers
 */

/* These might be defined from an include file, so undef them to be sure */

int tcpdemux::process_ip6(const be13::packet_info &pi)
{
    /* make sure that the packet is at least as long as the IPv6 header */
    if (pi.ip_datalen < sizeof(struct be13::ip6_hdr)) {
	DEBUG(6) ("received truncated IPv6 datagram!");
	return -1;
    }

    const struct be13::ip6_hdr *ip_header = (struct be13::ip6_hdr *) pi.ip_data;

    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
	return -1;
    }

    /* do TCP processing */
    uint16_t ip_payload_len = ntohs(ip_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
    ipaddr src(ip_header->ip6_src.addr.addr8);
    ipaddr dst(ip_header->ip6_dst.addr.addr8);
    
    return process_tcp(src, dst ,AF_INET6,
                       pi.ip_data + sizeof(struct be13::ip6_hdr),ip_payload_len,pi);
}



/* This is called when we receive an IPv4 or IPv6 datagram.
 * This function calls process_ip4 or process_ip6
 * Returns 0 if packet is processed, 1 if it is not processed, -1 if error.
 */

#pragma GCC diagnostic ignored "-Wcast-align"
int tcpdemux::process_pkt(const be13::packet_info &pi)
{
    int r = 1;                          // not processed yet
    switch(pi.ip_version()){
    case 4:
        r = process_ip4(pi);
        break;
    case 6:
        r = process_ip6(pi);
        break;
    }
    if(r!=0){                           // packet not processed?
        /* Write the packet if we didn't process it */
        if(pwriter) pwriter->writepkt(pi.pcap_hdr,pi.pcap_data);
    }
    return r;     
}
#pragma GCC diagnostic warning "-Wcast-align"
