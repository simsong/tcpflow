#ifndef FLOW_H
#define FLOW_H

/**
 * tcpdemux.h
 *
 * a tcpip demultiplier.
 *
 * Defines the basic classes used by the tcpflow program. This includes:
 * - IP, TCP and UDP structures
 * - class ipaddr    - IP address (IPv4 and IPv6)
 * - class flow_addr - The flow address (source addr & port; dest addr & port; family)
 * - class flow      - All of the information for a flow that's being tracked
 * - class tcp_header_t - convenience class for working with TCP headers
 * - class tcpip     - A one-sided TCP implementation
 * - class tcpdemux  - Processes individual packets, identifies flows,
 *                     and creates tcpip objects as required
 */

#include "md5.h"
#include <tr1/unordered_map>
#include <tr1/unordered_set>


#pragma GCC diagnostic ignored "-Weffc++"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wall"
#include <boost/icl/interval.hpp>
#include <boost/icl/interval_map.hpp>
#include <boost/icl/interval_set.hpp>
typedef boost::icl::interval_set<int> recon_set; // Boost interval set of bytes that were reconstructed.
#pragma GCC diagnostic warning "-Weffc++"
#pragma GCC diagnostic warning "-Wshadow"
#pragma GCC diagnostic warning "-Wall"


#ifdef WIN32
/* Defines not present in Microsoft Windows stack */
typedef uint8_t u_int8_t ;
typedef uint16_t u_int16_t ;
#define ETH_ALEN 6			// ethernet address len
#include "net_ethernet.h"
#endif

/** On windows, there is no in_addr_t; this is from
 * /usr/include/netinet/in.h
 */
#ifndef HAVE_NETINET_IN_H
typedef uint32_t in_addr_t;
#endif
#ifndef HAVE_SA_FAMILY_T
typedef unsigned short int sa_family_t;
#endif
#ifndef HAVE_TCP_SEQ
#ifdef WIN32
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

/*
 * Structure of an internet header, naked of options.
 */
struct ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4;		/* header length */
    uint8_t ip_v:4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4;		/* version */
    uint8_t ip_hl:4;		/* header length */
#endif
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
} __attribute__ ((__packed__));

typedef	uint32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
    uint16_t th_sport;		/* source port */
    uint16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4;		/* (unused) */
    uint8_t th_off:4;		/* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4;		/* data offset */
    uint8_t th_x2:4;		/* (unused) */
#  endif
    uint8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    uint16_t th_win;		/* window */
    uint16_t th_sum;		/* checksum */
    uint16_t th_urp;		/* urgent pointer */
};
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
    inline bool operator ==(const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))==0; };
    inline bool operator <=(const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))<=0; };
    inline bool operator > (const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))>0; };
    inline bool operator >=(const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(addr))>=0; };
    inline bool operator < (const ipaddr &b) const { return memcmp(this->addr,b.addr,sizeof(this->addr))<0; }

#pragma GCC diagnostic ignored "-Wcast-align"
    inline in_addr_t quad0() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[0]; }
    inline in_addr_t quad2() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[1]; }
    inline in_addr_t quad3() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[2]; }
    inline in_addr_t quad4() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[3]; }
    inline bool isv4() const {		// is this an IPv6 address?
	uint32_t *i = (uint32_t *)((uint8_t *)&addr);
	return i[1]==0 && i[2]==0 && i[3]==0;
    }
#pragma GCC diagnostic warning "-Wcast-align"
};

inline std::ostream & operator <<(std::ostream &os,const ipaddr &b)  {
    os << (int)b.addr[0] <<"."<<(int)b.addr[1] << "."
       << (int)b.addr[2] << "." << (int)b.addr[3];
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
    flow_addr(ipaddr s,ipaddr d,uint16_t sp,uint16_t dp,sa_family_t f):
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

#pragma GCC diagnostic ignored "-Wcast-align"
    uint64_t hash() const {
	if(family==AF_INET){
	    uint32_t *s =  (uint32_t *)src.addr; uint64_t S0 = s[0];
	    uint32_t *d =  (uint32_t *)dst.addr; uint64_t D0 = d[0];
	    return (S0<<32 | D0) ^ (D0<<32 | S0) ^ (sport<<16 | dport);
	} else {
	    uint64_t *s =  (uint64_t *)src.addr; uint64_t S0 = s[0];uint64_t S8 = s[1];
	    uint64_t *d =  (uint64_t *)dst.addr; uint64_t D0 = d[0];uint64_t D8 = d[1];
	    return (S0<<32 ^ D0) ^ (D0<<32 ^ S0) ^ (S8 ^ D8) ^ (sport<<16 | dport);
	}
    }
#pragma GCC diagnostic warning "-Wcast-align"

    inline bool operator ==(const flow_addr &b) const {
	return this->src==b.src &&
	    this->dst==b.dst &&
	    this->sport==b.sport &&
	    this->dport==b.dport &&
	    this->family==b.family;
    }

    inline bool operator <(const flow_addr &b) const {
	if (this->src<b.src) return true;
	if (this->src>b.src) return false;
	if (this->dst<b.dst) return true;
	if (this->dst>b.dst) return false;
	if (this->sport<b.sport) return true;
	if (this->sport>b.sport) return false;
	if (this->dport<b.dport) return true;
	if (this->dport>b.dport) return false;
	if (this->family < b.family) return true;
	if (this->family > b.family) return false;
	return false;    /* they are equal! */
    }
};

inline std::ostream & operator <<(std::ostream &os,const flow_addr &f)  {
    os << "flow[" << f.src << ":" << f.sport << "->" << f.dst << ":" << f.dport << "]";
    return os;
}


/*
 * A flow is a flow_addr that has additional information regarding when it was seen
 * and how many packets were seen. The address is used to locate the flow in the array.
 */
class flow : public flow_addr {
public:;
    static void usage();			// print information on flow notation
    static std::string filename_template;	// 
    static const int32_t NO_VLAN=-1;			/* vlan flag for no vlan */
    flow():id(),vlan(),tstart(),tlast(),packet_count(),connection_count(){};
    flow(const flow_addr &flow_addr_,int32_t vlan_,const struct timeval &t1,
	 const struct timeval &t2,uint64_t id_,uint64_t connection_count_):
	flow_addr(flow_addr_),id(id_),vlan(vlan_),tstart(t1),tlast(t2),
	packet_count(0),connection_count(connection_count_){}
    virtual ~flow(){};
    uint64_t  id;			// flow_counter when this flow was created
    int32_t   vlan;			// vlan interface we observed; -1 means no vlan 
    struct timeval tstart;		// when first seen
    struct timeval tlast;		// when last seen
    uint64_t packet_count;			// packet count
    uint64_t connection_count;		// how many times have we seen a flow with the same quad?
    std::string filename();		// returns filename for a flow based on the temlate
};

/*
 * Convenience class for working with TCP headers
 */
class tcp_header_t {
public:
#pragma GCC diagnostic ignored "-Wcast-align"
    tcp_header_t(const u_char *data):
	tcp_header((struct tcphdr *)data){};
#pragma GCC diagnostic warning "-Wcast-align"
    tcp_header_t(const tcp_header_t &b):
	tcp_header(b.tcp_header){}
    tcp_header_t &operator=(const tcp_header_t &that) {
	this->tcp_header = that.tcp_header;
	return *this;
    }

    virtual ~tcp_header_t(){}
    struct tcphdr *tcp_header;
    size_t tcp_header_len(){ return tcp_header->th_off * 4; }
    uint16_t sport() {return ntohs(tcp_header->th_sport);}
    uint16_t dport() {return ntohs(tcp_header->th_dport);}
    tcp_seq  seq()   {return ntohl(tcp_header->th_seq);}
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

class tcpip {
public:
    /** track the direction of the flow; this is largely unused */
    typedef enum {
	unknown=0,			// unknown direction
	dir_sc,				// server-to-client
	dir_cs				// client-to-server
    } dir_t;
	
private:
    /*** Begin Effective C++ error suppression                ***
     *** This class does not implement assignment or copying. ***
     ***/
    class not_impl: public std::exception {
	virtual const char *what() const throw() { return "copying tcpip objects is not implemented."; }
    };
    tcpip(const tcpip &t) __attribute__((__noreturn__)) : demux(t.demux),myflow(),dir(),isn(),nsn(),
			  syn_count(),pos(),
			  flow_pathname(),fd(),file_created(),
			  bytes_processed(),omitted_bytes(),
			  last_packet_number(),
			  out_of_order_count(),
			  violations(){
	throw new not_impl();
    }
    tcpip &operator=(const tcpip &that) { throw new not_impl(); }
    /*** End Effective C++ error suppression */

public:;
    tcpip(class tcpdemux &demux_,const flow &flow_,tcp_seq isn_);    /* constructor in tcpip.cpp */
    virtual ~tcpip();			// destructor

    class tcpdemux &demux;		// our demultiplexer


    /* State information for the flow being reconstructed */
    flow	myflow;			/* Description of this flow */
    dir_t	dir;			// direction of flow
    tcp_seq	isn;			// Flow's initial sequence number
    tcp_seq	nsn;			// fd - expected next sequence number 
    uint32_t	syn_count;		// has a SYN been seen?

    uint64_t	pos;			// fd - current position+1 (next byte in stream to be written)

    /* Archiving information */
    std::string flow_pathname;		// path where flow is stored
    int		fd;			// file descriptor for file storing this flow's data 
    bool	file_created;		// true if file was created



    /* Stats */
    uint64_t	bytes_processed;	// number of bytes processed by demultiplxier
    uint64_t    omitted_bytes;		// number of bytes not written to this file
    uint64_t	last_packet_number;	// for finding most recent packet
    uint64_t	out_of_order_count;	// all packets were contigious
    uint64_t    violations;		// protocol violation count

    /* Methods */
    void close_file();				// close fp
    void print_packet(const u_char *data, uint32_t length);
    void store_packet(const u_char *data, uint32_t length, int32_t delta);
    void process_packet(const struct timeval &ts,const int32_t delta,const u_char *data,const uint32_t length);
};

inline std::ostream & operator <<(std::ostream &os,const tcpip &f) {
    os << "tcpip[" << f.myflow << " isn:" << f.isn << " pos:" << f.pos << "]";
    return os;
}

/**
 * the tcp demultiplixer
 * This is a singleton class; we only need a single demultiplexer.
 */
class tcpdemux {
private:
    unsigned int get_max_fds(void);		// returns the max
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying tcpdemux objects is not implemented.";
	}
    };
    tcpdemux(const tcpdemux &t) __attribute__((__noreturn__)) :outdir("."),flow_counter(),packet_counter(),xreport(),
				max_fds(),flow_map(),start_new_connections(),openflows(),opt(),fs(){
	throw new not_impl();
    }
    tcpdemux &operator=(const tcpdemux &that){
	throw new not_impl();
    }

    /* see http://mikecvet.wordpress.com/tag/hashing/ */
    typedef struct {
	long operator() (const flow_addr &k) const {return k.hash(); }
    } flow_addr_hash;

    typedef struct {
	bool operator() (const flow_addr &x, const flow_addr &y) const { return x==y;}
    } flow_addr_key_eq;

    typedef std::tr1::unordered_set<class tcpip *> tcpset;
    typedef std::tr1::unordered_map<flow_addr,tcpip *,flow_addr_hash,flow_addr_key_eq> flow_map_t; // should be unordered_map
    tcpdemux();
public:
    /* The pure options class means we can add new options without having to modify the tcpdemux constructor. */
    class options {
    public:;
	enum { MAX_SEEK=1024*1024*16 };
	options():console_output(false),opt_output_enabled(true),opt_md5(false),
		  opt_post_processing(false),opt_gzip_decompress(true),
		  max_bytes_per_flow(),
		  max_desired_fds(),max_flows(0),suppress_header(0),
		  strip_nonprint(),use_color(0),max_seek(MAX_SEEK),
		  opt_no_purge(false) {
	}
	bool	console_output;
	bool	opt_output_enabled;	// do we output?
	bool	opt_md5;		// do we calculate MD5 on DFXML output?
	bool	opt_post_processing;	// decode headers after tcp connection closes
	bool	opt_gzip_decompress;
	uint64_t max_bytes_per_flow;
	uint32_t max_desired_fds;
	uint32_t max_flows;
	bool	suppress_header;
	bool	strip_nonprint;
	bool	use_color;
	int32_t max_seek;		// signed becuase we compare with abs()
	bool	opt_no_purge;
    };

    std::string outdir;			/* output directory */
    uint64_t	flow_counter;		// how many flows have we seen?
    uint64_t	packet_counter;		// monotomically increasing 
    xml		*xreport;		// DFXML output file
    unsigned int max_fds;		// maximum number of file descriptors for this tcpdemux

    flow_map_t	flow_map;		// the database
    bool	start_new_connections;	// true if we should start new connections
    tcpset	openflows;		// the tcpip flows with open FPs 
    options	opt;
    class feature_recorder_set *fs;
    
    static tcpdemux *getInstance();
    void  close_all();
    void  close_tcpip(tcpip *);
    int   open_tcpfile(tcpip *);			// opens this file; return -1 if failure, 0 if success
    void  close_oldest();
    void  remove_flow(const flow_addr &flow); // remove a flow from the database, closing open files if necessary
    int   retrying_open(const std::string &filename,int oflag,int mask);

    /* the flow database */
    tcpip *create_tcpip(const flow_addr &flow, int32_t vlan,tcp_seq isn, const timeval &ts,uint64_t connection_count);
    tcpip *find_tcpip(const flow_addr &flow);

    void  process_tcp(const struct timeval &ts,const u_char *data, uint32_t length,
			    const ipaddr &src, const ipaddr &dst,int32_t vlan,sa_family_t family);
    void  process_ip4(const struct timeval &ts,const u_char *data, uint32_t caplen,int32_t vlan);
    void  process_ip6(const struct timeval &ts,const u_char *data, const uint32_t caplen, const int32_t vlan);
    void  process_ip(const struct timeval &ts,const u_char *data, uint32_t caplen,int32_t vlan);
    void  flow_map_clear();		// clears out the map
};

#endif
