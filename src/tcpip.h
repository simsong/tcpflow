#ifndef TCPIP_H
#define TCPIP_H

#include <fstream>

#include "inet_ntop.h"

/** On windows, there is no in_addr_t; this is from
 * /usr/include/netinet/in.h
 */
#ifndef HAVE_NETINET_IN_H
typedef uint32_t in_addr_t;
#endif

#ifndef HAVE_SA_FAMILY_T
typedef unsigned short int sa_family_t;
#endif


/**
 * ipaddress class.
 * represents IPv4 and IPv6 addresses.
 * IPv4 addresses have address in bytes 0..3 and all NULL for bytes 4..11
 */
class ipaddr {
public:;
    ipaddr(){
	memset(addr,0,sizeof(addr));
    }
    ipaddr(const in_addr_t &a){		// copy operator
	addr[0] = ((uint8_t *)&a)[0];	// copy the bottom 4 octets and blank the top 12
	addr[1] = ((uint8_t *)&a)[1];
	addr[2] = ((uint8_t *)&a)[2];
	addr[3] = ((uint8_t *)&a)[3];
	memset(addr+4,0,12);
    }
    ipaddr(const uint8_t a[16]){	// begin wiped
	memcpy(addr,a,16);
    }

    uint8_t addr[16];			// holds v4 or v16
    bool bit(int i) const {             // get the ith bit; 0 is MSB
        return (addr[i / 8]) & (1<<(7-i%8));
    }
    uint32_t quad(int i) const {        // gets the ith quad as a 32-bit value
        return (addr[i*4+0]<<24) | (addr[i*4+2]<<16) | (addr[i*4+1]<<8) |  (addr[i*4+3]<<0);
    }
    uint64_t dquad(int i) const {       // gets the first 64-bit half or the second 64-bit half
        return (uint64_t)(quad(i*2+1))<<32 | (uint64_t)(quad(i*2));
    }
        
    inline bool operator ==(const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))==0; };
    inline bool operator <=(const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))<=0; };
    inline bool operator > (const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))>0; };
    inline bool operator >=(const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))>=0; };
    inline bool operator < (const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(this->addr))<0; }
};

class ipaddr_prn {
public:
    const ipaddr& ia;
    const sa_family_t family;
    ipaddr_prn(const ipaddr& ia_, sa_family_t family_)
        : ia(ia_), family(family_)
    { }
};

inline std::ostream & operator <<(std::ostream &os, const ipaddr_prn &b) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(b.family, b.ia.addr, buf, sizeof(buf));
    os << buf;
    return os;
}

inline bool operator ==(const struct timeval &a,const struct timeval &b) {
    return a.tv_sec==b.tv_sec && a.tv_usec==b.tv_usec;
}

inline bool operator <(const struct timeval &a,const struct timeval &b) {
    return (a.tv_sec<b.tv_sec) || ((a.tv_sec==b.tv_sec) && (a.tv_sec<b.tv_sec));
}

/*
 * describes the TCP flow.
 * No timing information; this is used as a map index.
 */
class flow_addr {
public:
    flow_addr():src(),dst(),sport(0),dport(0),family(0){ }
    flow_addr(const ipaddr &s,const ipaddr &d,uint16_t sp,uint16_t dp,sa_family_t f):
	src(s),dst(d),sport(sp),dport(dp),family(f){
    }
    flow_addr(const flow_addr &f):src(f.src),dst(f.dst),sport(f.sport),dport(f.dport),
				  family(f.family){
    }
    virtual ~flow_addr(){};
    ipaddr	src;		// Source IP address; holds v4 or v6 
    ipaddr	dst;		// Destination IP address; holds v4 or v6 
    uint16_t    sport;		// Source port number 
    uint16_t    dport;		// Destination port number 
    sa_family_t family;		// AF_INET or AF_INET6 */

    uint64_t hash() const {
	if(family==AF_INET){
	    return ((uint64_t)(src.quad(0))<<32 | dst.quad(0))
                ^ ((uint64_t)(dst.quad(0))<<32 | src.quad(0))
                ^ (sport<<16 | dport);
	} else {
	    return (src.dquad(0)<<32 ^ dst.dquad(0))
                ^ (dst.dquad(0)<<32  ^ src.dquad(0))
                ^ (src.dquad(1)      ^ dst.dquad(1))
                ^ (sport<<16 | dport);
	}
    }

    inline bool operator ==(const flow_addr &b) const {
	return this->src==b.src &&
	    this->dst==b.dst &&
	    this->sport==b.sport &&
	    this->dport==b.dport &&
	    this->family==b.family;
    }

    inline bool operator <(const flow_addr &b) const {
	if (this->src < b.src) return true;
	if (this->src > b.src) return false;
	if (this->dst < b.dst) return true;
	if (this->dst > b.dst) return false;
	if (this->sport < b.sport) return true;
	if (this->sport > b.sport) return false;
	if (this->dport < b.dport) return true;
	if (this->dport > b.dport) return false;
	if (this->family < b.family) return true;
	if (this->family > b.family) return false;
	return false;    /* they are equal! */
    }

    std::string str() const {
        std::stringstream s;
        s << "flow[" << ipaddr_prn(src, family) << ":" << sport << "->" << ipaddr_prn(dst, family) << ":" << dport << "]";
        return s.str();
    }
};

inline std::ostream & operator <<(std::ostream &os,const flow_addr &f)  {
    os << f.str();
    return os;
}


/*
 * A flow is a flow_addr that has additional information regarding when it was seen
 * and how many packets were seen. The address is used to locate the flow in the array.
 * Notice that it contains no pointers, so it can be copied with the default operator.
 */
class flow : public flow_addr {
public:;
    static void usage();			// print information on flow notation
    static std::string filename_template;	// 
    static std::string outdir;                  // where the output gets written
    flow():id(),vlan(),mac_daddr(),mac_saddr(),tstart(),tlast(),len(),caplen(),packet_count(),session_id(){};
    flow(const flow_addr &flow_addr_,uint64_t id_,const be13::packet_info &pi):
	flow_addr(flow_addr_),id(id_),vlan(pi.vlan()),
        mac_daddr(),
        mac_saddr(),
        tstart(pi.ts),tlast(pi.ts),
        len(0),
        caplen(0),
	packet_count(0),
        session_id(0) {
        if(pi.pcap_hdr){
            memcpy(mac_daddr,pi.get_ether_dhost(),sizeof(mac_daddr));
            memcpy(mac_saddr,pi.get_ether_shost(),sizeof(mac_saddr));
        }
    }
    virtual ~flow(){};
    uint64_t  id;			// flow_counter when this flow was created
    int32_t   vlan;			// vlan interface we first observed; -1 means no vlan 
    uint8_t mac_daddr[6];               // dst mac address of first packet
    uint8_t mac_saddr[6];               // source mac address of first packet
    struct timeval tstart;		// when first seen
    struct timeval tlast;		// when last seen
    uint64_t len;     		        // off-wire length
    uint64_t caplen;    		// captured length
    uint64_t packet_count;		// packet count
    uint64_t session_id;      // session unique id (used to match client->server and server->client flows

    // return a filename for a flow based on the template and the connection count
    std::string filename(uint32_t connection_count, bool);
    // return a new filename for a flow based on the temlate,
    // optionally opening the file and returning a fd if &fd is provided
    std::string new_filename(int *fd,int flags,int mode);	

    std::string new_pcap_filename();

    bool has_mac_daddr(){
        return mac_daddr[0] || mac_daddr[1] || mac_daddr[2] || mac_daddr[3] || mac_daddr[4] || mac_daddr[5];
    }

    bool has_mac_saddr(){
        return mac_saddr[0] || mac_saddr[1] || mac_saddr[2] || mac_saddr[3] || mac_saddr[4] || mac_saddr[5];
    }
};

/*
 * Convenience class for working with TCP headers
 */
#define PORT_HTTP 80
#define PORT_HTTP_ALT_0 8080
#define PORT_HTTP_ALT_1 8000
#define PORT_HTTP_ALT_2 8888
#define PORT_HTTP_ALT_3 81
#define PORT_HTTP_ALT_4 82
#define PORT_HTTP_ALT_5 8090
#define PORT_HTTPS 443
#define PORT_SSH 22
#define PORT_FTP_DATA 20
#define PORT_FTP_CONTROL 21
class tcp_header_t {
public:
#pragma GCC diagnostic ignored "-Wcast-align"
    tcp_header_t(const u_char *data):
	tcp_header((struct be13::tcphdr *)data){};
#pragma GCC diagnostic warning "-Wcast-align"
    tcp_header_t(const tcp_header_t &b):
	tcp_header(b.tcp_header){}
    tcp_header_t &operator=(const tcp_header_t &that) {
	this->tcp_header = that.tcp_header;
	return *this;
    }

    virtual ~tcp_header_t(){}
    struct be13::tcphdr *tcp_header;
    size_t tcp_header_len(){ return tcp_header->th_off * 4; }
    uint16_t sport() {return ntohs(tcp_header->th_sport);}
    uint16_t dport() {return ntohs(tcp_header->th_dport);}
    be13::tcp_seq  seq()   {return ntohl(tcp_header->th_seq);}
    bool th_fin()    {return tcp_header->th_flags & TH_FIN;}
    bool th_ack()    {return tcp_header->th_flags & TH_ACK;}
    bool th_syn()    {return tcp_header->th_flags & TH_SYN;}
};


/*
 * The tcpip class is a passive tcp/ip implementation.
 * It can reconstruct flows!
 *
 * It includes:
 *   - the flow (as an embedded object)
 *   - Information about where the flow is written.
 *   - Information about how much of the flow has been captured.
 * Currently flows only go in one direction and do not know about their sibling flow
 */

#pragma GCC diagnostic ignored "-Weffc++"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wall"
#pragma GCC diagnostic ignored "-Wmissing-noreturn"

#if defined(HAVE_BOOST_ICL_INTERVAL_HPP) && defined(HAVE_BOOST_ICL_INTERVAL_MAP_HPP) && defined(HAVE_BOOST_ICL_INTERVAL_SET_HPP)
#include <boost/icl/interval.hpp>
#include <boost/icl/interval_map.hpp>
#include <boost/icl/interval_set.hpp>
typedef boost::icl::interval_set<uint64_t> recon_set; // Boost interval set of bytes that were reconstructed.
#endif

#include "intrusive_list.h"

#pragma GCC diagnostic warning "-Weffc++"
#pragma GCC diagnostic warning "-Wshadow"
#pragma GCC diagnostic warning "-Wall"
#pragma GCC diagnostic warning "-Wmissing-noreturn"

class tcpip {
public:
    /** track the direction of the flow; this is largely unused */
    typedef enum {
	unknown=0,			// unknown direction
	dir_sc,				// server-to-client 1 
	dir_cs				// client-to-server 2
    } dir_t;
	
private:
    /*** Begin Effective C++ error suppression                ***
     *** This class does not implement assignment or copying. ***
     ***/
    tcpip(const tcpip &t);
    tcpip &operator=(const tcpip &that);
    /*** End Effective C++ error suppression */

public:;
    tcpip(class tcpdemux &demux_,const flow &flow_,be13::tcp_seq isn_);    /* constructor in tcpip.cpp */
    virtual ~tcpip();			// destructor

    class tcpdemux &demux;		// our demultiplexer

    /* State information for the flow being reconstructed */
    flow	myflow;			/* Description of this flow */
    dir_t	dir;			// direction of flow
    be13::tcp_seq isn;			// Flow's initial sequence number
    be13::tcp_seq nsn;			// fd - expected next sequence number 
    uint32_t	syn_count;		// number of SYNs seen
    uint32_t    fin_count;              // number of FINs received
    uint32_t    fin_size;               // length of stream as determined when fin is sent
    uint64_t	pos;			// fd - current position+1 (next byte in stream to be written)

    /* Archiving information */
    std::string flow_pathname;		// path where flow is saved
    int		fd;			// file descriptor for file storing this flow's data 
    bool	file_created;		// true if file was created

    /* Flow Index information - only used if flow packet/data indexing is requested --GDD */
    std::string flow_index_pathname;	// Path for the flow index file
    std::fstream		idx_file;				// File descriptor for storing the flow index data

    /* Stats */
    recon_set   *seen;                  // what we've seen; it must be * due to boost lossage
    uint64_t    last_byte;              // last byte in flow processed
    uint64_t	last_packet_number;	// for finding most recent packet written
    uint64_t	out_of_order_count;	// all packets were contigious
    uint64_t    violations;		// protocol violation count

    /* File Acess Order */
    intrusive_list<tcpip>::iterator it;

    /* Methods */
    void close_file();			// close fd
    int  open_file();                   // opens save file; return -1 if failure, 0 if success
    void print_packet(const u_char *data, uint32_t length);
    void store_packet(const u_char *data, uint32_t length, int32_t delta,struct timeval ts);
    void process_packet(const struct timeval &ts,const int32_t delta,const u_char *data,const uint32_t length);
    uint32_t seen_bytes();
    void dump_seen();
    void dump_xml(class dfxml_writer *xmlreport,const std::string &xmladd);
    static bool compare(std::string a, std::string b);
    void sort_index(std::fstream *idx_file);
    void sort_index();
};

/* print a tcpip data structure. Largely for debugging */
inline std::ostream & operator <<(std::ostream &os,const tcpip &f) {
    os << "tcpip[" << f.myflow
       << " dir:" << int(f.dir) << " isn:" << f.isn << " nsn: " << f.nsn
       << " sc:" << f.syn_count << " fc:" << f.fin_count << " fs:" << f.fin_size
       << " pos:" << f.pos << " fd: " << f.fd << " cr:" << f.file_created 
       << " lb:" << f.last_byte << " lpn:" << f.last_packet_number << " ooc:" << f.out_of_order_count
       << "]";
    if(f.fd>0) os << " ftell(" << f.fd << ")=" << lseek(f.fd,0L,SEEK_CUR);
    return os;
}

/*
 * An saved_flow is a flow for which all of the packets have been received and tcpip state
 * has been discarded. The saved_flow allows matches against newly received packets
 * that are not SYN or ACK packets but have data. We can see if the data matches data that's
 * been written to disk. To do this we need ot know the filename and the ISN...
 */

class saved_flow  {
public:
    saved_flow(tcpip *tcp):addr(tcp->myflow),
                           saved_filename(tcp->flow_pathname),
                           isn(tcp->isn) {}
                           
    flow_addr         addr;                  // flow address
    std::string       saved_filename;        // where the flow was saved
    be13::tcp_seq     isn;                    // the flow's ISN
    virtual ~saved_flow(){};
};

class sparse_saved_flow  {
public:
    sparse_saved_flow (const flow_addr &idx, FILE *_fcap):addr(idx),fcap(_fcap) {}

    flow_addr         addr;                  // flow address
    FILE              *fcap;                // output pcap file
    virtual ~sparse_saved_flow()
    {
        if(fcap) fclose(fcap);
    }
    /* these are not implemented */
private:
    sparse_saved_flow(const sparse_saved_flow &t);
    sparse_saved_flow &operator=(const sparse_saved_flow &that);
};


#endif
