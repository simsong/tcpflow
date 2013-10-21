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

#include "pcap_writer.h"
#include "dfxml/src/dfxml_writer.h"
#include "dfxml/src/hash_t.h"
#if defined(HAVE_UNORDERED_MAP)
# include <unordered_map>
# undef HAVE_TR1_UNORDERED_MAP           // be sure we don't use it
#else
# if defined(HAVE_TR1_UNORDERED_MAP)
#  include <tr1/unordered_map>
# else
#  error Requires <unordered_map> or <tr1/unordered_map>
# endif
#endif

#if defined(HAVE_UNORDERED_SET)
#include <unordered_set>
#undef HAVE_TR1_UNORDERED_SET           // be sure we don't use it
#else
#if defined(HAVE_TR1_UNORDERED_SET)
#include <tr1/unordered_set>
#else
#error Requires <unordered_set> or <tr1/unordered_set>
#endif
#endif

#include <queue>


/**
 * the tcp demultiplixer
 * This is a singleton class; we only need a single demultiplexer.
 */
class tcpdemux {
private:
    class not_impl: public std::exception {
        virtual const char *what() const throw() {
            return "copying tcpdemux objects is not implemented.";
        }
    };
    tcpdemux(const tcpdemux &t) __attribute__((__noreturn__)) :outdir("."),flow_counter(),packet_counter(),xreport(),pwriter(),
        max_open_flows(),max_fds(),flow_map(),open_flows(),saved_flow_map(),saved_flows(),start_new_connections(),opt(),fs(){
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

#ifdef HAVE_TR1_UNORDERED_MAP
    typedef std::tr1::unordered_set<class tcpip *> tcpset;
    typedef std::tr1::unordered_map<flow_addr,tcpip *,flow_addr_hash,flow_addr_key_eq> flow_map_t; // active flows
    typedef std::tr1::unordered_map<flow_addr,saved_flow *,flow_addr_hash,flow_addr_key_eq> saved_flow_map_t; // flows that have been saved
#else
    typedef std::unordered_set<class tcpip *> tcpset;
    typedef std::unordered_map<flow_addr,tcpip *,flow_addr_hash,flow_addr_key_eq> flow_map_t; // active flows
    typedef std::unordered_map<flow_addr,saved_flow *,flow_addr_hash,flow_addr_key_eq> saved_flow_map_t; // flows that have been saved
#endif
    typedef std::vector<class saved_flow *> saved_flows_t; // needs to be ordered


    tcpdemux();
public:
    static uint32_t tcp_timeout;
    static unsigned int get_max_fds(void);             // returns the max
    virtual ~tcpdemux(){
        if(xreport) delete xreport;
        if(pwriter) delete pwriter;
    }

    /* The pure options class means we can add new options without having to modify the tcpdemux constructor. */
    class options {
    public:;
        enum { MAX_SEEK=1024*1024*16 };
        options():console_output(false),store_output(true),opt_md5(false),
                  post_processing(false),gzip_decompress(true),
                  max_bytes_per_flow(),
                  max_flows(0),suppress_header(0),
                  output_strip_nonprint(true),output_hex(false),use_color(0),max_seek(MAX_SEEK){
        }
        bool    console_output;
        bool    store_output;   // do we output?
        bool    opt_md5;                // do we calculate MD5 on DFXML output?
        bool    post_processing;        // decode headers after tcp connection closes
        bool    gzip_decompress;
        uint64_t max_bytes_per_flow;
        uint32_t max_flows;
        bool    suppress_header;
        bool    output_strip_nonprint;
        bool    output_hex;
        bool    use_color;
        int32_t max_seek;               // signed becuase we compare with abs()
    };

    enum { WARN_TOO_MANY_FILES=10000};  // warn if more than this number of files in a directory

    std::string outdir;                 /* output directory */
    uint64_t    flow_counter;           // how many flows have we seen?
    uint64_t    packet_counter;         // monotomically increasing 
    dfxml_writer  *xreport;               // DFXML output file
    pcap_writer *pwriter;               // where we should write packets
    unsigned int max_open_flows;        // how large did it ever get?
    unsigned int max_fds;               // maximum number of file descriptors for this tcpdemux

    flow_map_t  flow_map;               // db of open tcpip objects, indexed by flow
    tcpset      open_flows;              // the tcpip flows with open files

    saved_flow_map_t saved_flow_map;  // db of saved flows, indexed by flow
    saved_flows_t    saved_flows;     // the flows that were saved
    bool             start_new_connections;  // true if we should start new connections

    options     opt;
    class       feature_recorder_set *fs; // where features extracted from each flow should be stored
    
    static uint32_t max_saved_flows;       // how many saved flows are kept in the saved_flow_map
    static tcpdemux *getInstance();

    void  save_unk_packets(const std::string &wfname,const std::string &ifname); // save unknown packets at this location
    void  post_process(tcpip *tcp);      // just before closing; writes XML and closes fd

    /* management of open fds and in-process tcpip flows*/
    void  close_all_fd();
    void  close_tcpip_fd(tcpip *);         
    void  close_oldest_fd();
    void  remove_flow(const flow_addr &flow); // remove a flow from the database, closing open files if necessary
    void  remove_all_flows();                 // stop processing all tcpip connections

    /* open a new file, closing an fd in the openflow database if necessary */
    int   retrying_open(const std::string &filename,int oflag,int mask);

    /* the flow database holds in-process tcpip connections */
    tcpip *create_tcpip(const flow_addr &flow, be13::tcp_seq isn, const be13::packet_info &pi);
    tcpip *find_tcpip(const flow_addr &flow);

    /* saved flows are completed flows that we remember in case straggling packets
     * show up. Remembering the flows lets us resolve the packets rather than creating
     * new flows.
     */
    void  save_flow(tcpip *);

    /** packet processing.
     * Each returns 0 if processed, 1 if not processed, -1 if error.
     */
    int  process_tcp(const ipaddr &src, const ipaddr &dst,sa_family_t family,
                     const u_char *tcp_data, uint32_t tcp_length,
                     const be13::packet_info &pi);
    int  process_ip4(const be13::packet_info &pi);
    int  process_ip6(const be13::packet_info &pi);
    int  process_pkt(const be13::packet_info &pi);
};


#endif
