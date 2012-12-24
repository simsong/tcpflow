#ifndef TCPDEMUX_H
#define TCPDEMUX_H

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
				max_fds(),flow_map(),openflows(),start_new_connections(),opt(),fs(){
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
	options():console_output(false),store_output(true),opt_md5(false),
		  post_processing(false),opt_gzip_decompress(true),
		  max_bytes_per_flow(),
		  max_desired_fds(),max_flows(0),suppress_header(0),
		  strip_nonprint(),use_color(0),max_seek(MAX_SEEK),
		  opt_no_purge(false) {
	}
	bool	console_output;
	bool	store_output;	// do we output?
	bool	opt_md5;		// do we calculate MD5 on DFXML output?
	bool	post_processing;	// decode headers after tcp connection closes
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

    flow_map_t	flow_map;		// db of flow->tcpip objects
    tcpset	openflows;		// the tcpip flows with open files
    bool	start_new_connections;	// true if we should start new connections
    options	opt;
    class feature_recorder_set *fs;
    
    static tcpdemux *getInstance();
    void  close_all();
    void  close_tcpip(tcpip *);
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
