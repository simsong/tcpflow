#ifndef FLOW_H
#define FLOW_H

/*
 * tcpdemux.h
 * defines the basic classes used by the tcpflow program.
 */


#include "md5.h"
#include <tr1/unordered_map>
#include <tr1/unordered_set>

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
    ipaddr(const in_addr_t &a){
	addr[0] = ((uint8_t *)&a)[0];
	addr[1] = ((uint8_t *)&a)[1];
	addr[2] = ((uint8_t *)&a)[2];
	addr[3] = ((uint8_t *)&a)[3];
	memset(addr+4,0,12);
    }
    ipaddr(const uint8_t a[16]){
	memcpy(addr,a,16);
    }

    u_int8_t addr[16];			// holds v4 or v16
    inline bool operator ==(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))==0;
    };
    inline bool operator <=(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))<=0;
    };
    inline bool operator >(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))>0;
    };
    inline bool operator >=(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))>=0;
    };
    inline bool operator <(const ipaddr &b) const {
	return  memcmp(this->addr,b.addr,sizeof(this->addr))<0;
    }
    inline in_addr_t quad0() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[0]; }
    inline in_addr_t quad2() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[1]; }
    inline in_addr_t quad3() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[2]; }
    inline in_addr_t quad4() const { uint32_t *i = (uint32_t *)((uint8_t *)&addr); return i[3]; }
    inline bool isv4() const {
	uint32_t *i = (uint32_t *)((uint8_t *)&addr);
	return i[1]==0 && i[2]==0 && i[3]==0;
    }
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
    flow_addr():src(),dst(),sport(0),dport(0),family(0){
    }
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
	if (this->family > b.family) return true;
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
    static void print_usage();
    static std::string filename_template;	// 
    static int32_t NO_VLAN;			/* vlan flag for no vlan */
    flow():id(),vlan(),tstart(),tlast(),packet_count(),connection_count(){};
    flow(const flow_addr &flow_addr_,int32_t vlan_,const struct timeval &t1,
	   const struct timeval &t2,uint64_t id_,uint64_t connection_count_):
	flow_addr(flow_addr_),id(id_),vlan(vlan_),tstart(t1),tlast(t2),
	packet_count(0),connection_count(connection_count_){}
    virtual ~flow(){};
    uint64_t id;			// flow_counter when this flow was created
    int32_t	vlan;			// vlan interface we observed; -1 means no vlan 
    struct timeval tstart;		// when first seen
    struct timeval tlast;		// when last seen
    uint64_t packet_count;			// packet count
    uint64_t connection_count;	// how many times have we seen a flow with the same addr?
    std::string filename();		// returns filename for a flow based on the temlate
};

/*
 * Convenience class for working with TCP headers
 */
class tcp_header_t {
public:
    tcp_header_t(const u_char *data):
	tcp_header((struct tcphdr *)data){};
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


/* see http://mikecvet.wordpress.com/tag/hashing/ */
typedef struct {
    long operator() (const flow_addr &k) const {return k.hash(); }
} flow_addr_hash;

typedef struct {
    bool operator() (const flow_addr &x, const flow_addr &y) const { return x==y;}
} flow_addr_key_eq;


/*
 * A tcpip is a flow with an initial sequence number.
 * We might be able to make this a subclass of a flow,
 * but that doesn't seem right, since the tcpip structure
 * also has information about where the flow is written.
 */

class tcpip {
public:
    typedef enum {
	unknown=0,			// unknown direction
	dir_sc,				// server-to-client
	dir_cs				// client-to-server
    } dir_t;
	
private:
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying tcpip objects is not implemented.";
	}
    };
    tcpip(const tcpip &t):demux(t.demux),myflow(),isn(),flow_pathname(),fp(),pos(),pos_max(),last_packet_time(),
			  bytes_printed(),
			  finished(),file_created(),dir(),out_of_order_count(),md5(){
	throw new not_impl();
    }
    tcpip &operator=(const tcpip &that) {
	throw new not_impl();
    }
public:;
    /* instances - individual tcp/ip flows */
    tcpip(class tcpdemux &demux_,const flow &flow_,tcp_seq isn_);    /* constructors */
    virtual ~tcpip();			// destructor
    class tcpdemux &demux;		// our demultiplexer
    flow	myflow;			/* Description of this flow */
    tcp_seq	isn;			// Flow's initial sequence number
    std::string flow_pathname;		// path where flow is stored
    FILE	*fp;			// Pointer to file storing this flow's data 
    uint64_t	pos;			// Current write position in fp 
    uint64_t	pos_max;		// highest pos has gotten
    int		last_packet_time;	// packet_timegtre of last access; used to sort the open flows to figure out which to close 
    uint64_t	bytes_printed;		// for -b and -c used together
    bool	finished;
    bool	file_created;		// true if file was created
    dir_t	dir;			// direction of flow
    uint64_t	out_of_order_count;		// all packets were contigious
    context_md5_t *md5;			// md5 context if MD5 calculation in use

    /* Methods */
    void process_gzip(std::stringstream &ss,
		      const std::string &fname,const unsigned char *base,size_t len);
    void close_file();				// close fp
    void print_packet(const u_char *data, u_int32_t length);
    void store_packet(const u_char *data, u_int32_t length, u_int32_t seq, int syn_set);
};

inline std::ostream & operator <<(std::ostream &os,const tcpip &f) {
    os << "tcpip[" << f.myflow << " isn:" << f.isn << " pos:" << f.pos << "]";
    return os;
}


/**
 * the tcp demultiplixer
 */
class tcpdemux {
private:
    unsigned int get_max_fds(void);		// returns the max
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying tcpdemux objects is not implemented.";
	}
    };
    tcpdemux(const tcpdemux &t):outdir(),flow_counter(),packet_time(),xreport(),max_fds(),flow_map(),openflows(),opt_output_enabled(),
				opt_md5(),opt_after_header(),opt_gzip_decompress(),
				max_bytes_per_flow(),max_desired_fds(){
	throw new not_impl();
    }
    tcpdemux &operator=(const tcpdemux &that){
	throw new not_impl();
    }
public:
    typedef std::tr1::unordered_set<class tcpip *> tcpset;
    typedef std::tr1::unordered_map<flow_addr,tcpip *,flow_addr_hash,flow_addr_key_eq> flow_map_t; // should be unordered_map
    std::string outdir;		/* output directory */
    uint64_t	flow_counter;	// how many flows have we seen?
    uint64_t	packet_time;	// monotomically increasing time
    xml		*xreport;		// DFXML output file
    unsigned int max_fds;		// maximum number of file descriptors for this tcpdemux

    flow_map_t	flow_map;		// the database
    tcpset	openflows;		// the tcpip flows with open FPs 
    bool	opt_output_enabled;	// do we output?
    bool	opt_md5;		// do we calculate MD5 on DFXML output?
    bool	opt_after_header;	// decode headers after tcp connection closes
    bool	opt_gzip_decompress;
    uint64_t	max_bytes_per_flow;
    int		max_desired_fds;
    
    tcpdemux();
    void write_to_file(std::stringstream &ss,
		       const std::string &fname,const uint8_t *base,const uint8_t *buf,size_t buflen);
    void	close_all();
    void	close_tcpip(tcpip *);
    int		open_tcpfile(tcpip *);			// opens this file; return -1 if failure, 0 if success
    void	close_oldest();
    void	remove_flow(const flow_addr &flow); // remove a flow from the database, closing open files if necessary
    int		retrying_open(const char *filename,int oflag,int mask);
    FILE	*retrying_fopen(const char *filename,const char *mode);

    /* the flow database */
    tcpip *create_tcpip(const flow_addr &flow, int32_t vlan,tcp_seq isn,
			       const timeval &ts,uint64_t connection_count);
    tcpip *find_tcpip(const flow_addr &flow);
    void process_tcp(const struct timeval *ts,const u_char *data, u_int32_t length,
			    const ipaddr &src, const ipaddr &dst,int32_t vlan,sa_family_t family);
    void process_ip4(const struct timeval *ts,const u_char *data, u_int32_t caplen,int32_t vlan);
    void process_ip6(const struct timeval *ts,const u_char *data, const u_int32_t caplen, const int32_t vlan);
    void process_ip(const struct timeval *ts,const u_char *data, u_int32_t caplen,int32_t vlan);
    void flow_map_clear();		// clears out the map
};

inline std::ostream & operator << (std::ostream &os,const tcpdemux::flow_map_t &fm) {
    for(tcpdemux::flow_map_t::const_iterator it=fm.begin();it!=fm.end();it++){
	os << "first: " << it->first << " second: " << *it->second << "\n";
    }
    return os;
};

#endif
