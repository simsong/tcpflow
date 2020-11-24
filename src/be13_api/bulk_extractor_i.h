/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * By design, this file can be read without reading config.h
 * #include "config.h" must appear as the first line of your .cpp file.
 */

#ifndef PACKAGE_NAME
#error bulk_extractor_i.h included before config.h
#endif

#ifndef BULK_EXTRACTOR_I_H
#define BULK_EXTRACTOR_I_H

#define DEBUG_PEDANTIC    0x0001        // check values more rigorously
#define DEBUG_PRINT_STEPS 0x0002        // prints as each scanner is started
#define DEBUG_SCANNER     0x0004        // dump all feature writes to stderr
#define DEBUG_NO_SCANNERS 0x0008        // do not run the scanners
#define DEBUG_DUMP_DATA   0x0010        // dump data as it is seen
#define DEBUG_DECODING    0x0020        // debug decoders in scanner
#define DEBUG_INFO        0x0040        // print extra info
#define DEBUG_EXIT_EARLY  1000          // just print the size of the volume and exis 
#define DEBUG_ALLOCATE_512MiB 1002      // Allocate 512MiB, but don't set any flags 

/* We need netinet/in.h or windowsx.h */
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <assert.h>

#if defined(MINGW) || defined(__MINGW__) || defined(__MINGW32__) || defined(__MINGW64__)
#ifndef WIN32
#define WIN32
#endif
#endif

#if defined(WIN32) || defined(__MINGW32__)
#  include <winsock2.h>
#  include <windows.h>
#  include <windowsx.h>
#endif

/* If byte_order hasn't been defined, assume its intel */

#if defined(WIN32) || !defined(__BYTE_ORDER)
#  define __LITTLE_ENDIAN 1234
#  define __BIG_ENDIAN    4321
#  define __BYTE_ORDER __LITTLE_ENDIAN
#endif

#if (__BYTE_ORDER == __LITTLE_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN)
#  error Invalid __BYTE_ORDER
#endif

/**
 * \addtogroup plugin_module
 * @{
 */

/**
 * \file
 * bulk_extractor scanner plug_in architecture.
 *
 * Scanners are called with two parameters:
 * A reference to a scanner_params (SP) object.
 * A reference to a recursion_control_block (RCB) object.
 * 
 * On startup, each scanner is called with a special SP and RCB.
 * The scanners respond by setting fields in the SP and returning.
 * 
 * When executing, once again each scanner is called with the SP and RCB.
 * This is the only file that needs to be included for a scanner.
 *
 * \li \c phase_startup - scanners are loaded and register the names of the feature files they want.
 * \li \c phase_scan - each scanner is called to analyze 1 or more sbufs.
 * \li \c phase_shutdown - scanners are given a chance to shutdown
 */

#ifndef __cplusplus
# error bulk_extractor_i.h requires C++
#endif

#include "sbuf.h"
#include "utf8.h"
#include "utils.h"                      // for gmtime_r

#include <vector>
#include <set>
#include <map>

#include "feature_recorder.h"
#include "feature_recorder_set.h"

/* Network includes */

/****************************************************************
 *** pcap.h --- If we don't have it, fake it. ---
 ***/
#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_NET_ETHERNET_H
# include <net/ethernet.h>              // for freebsd
#endif


#if defined(HAVE_LIBPCAP)
#  ifdef HAVE_DIAGNOSTIC_REDUNDANT_DECLS
#    pragma GCC diagnostic ignored "-Wredundant-decls"
#  endif
#  if defined(HAVE_PCAP_PCAP_H)
#    include <pcap/pcap.h>
#    define GOT_PCAP
#  endif
#  if defined(HAVE_PCAP_H) && !defined(GOT_PCAP)
#    include <pcap.h>
#    define GOT_PCAP
#  endif
#  if defined(HAVE_WPCAP_PCAP_H) && !defined(GOT_PCAP)
#    include <wpcap/pcap.h>
#    define GOT_PCAP
#  endif
#  ifdef HAVE_DIAGNOSTIC_REDUNDANT_DECLS
#    pragma GCC diagnostic warning "-Wredundant-decls"
#  endif
#else
#  include "pcap_fake.h"
#endif

/**
 * \class scanner_params
 * The scanner params class is the primary way that the bulk_extractor framework
 * communicates with the scanners. 
 * @param sbuf - the buffer to be scanned
 * @param feature_names - if fs==0, add to feature_names the feature file types that this
 *                        scanner records.. The names can have a /c appended to indicate
 *                        that the feature files should have context enabled. Do not scan.
 * @param fs   - where the features should be saved. Must be provided if feature_names==0.
 **/

/*****************************************************************
 *** bulk_extractor has a private implementation of IPv4 and IPv6,
 *** UDP and TCP. 
 ***
 *** We did this becuase we found slightly different versions on
 *** MacOS, Ubuntu Linux, Fedora Linux, Centos, Mingw, and Cygwin.
 *** TCP/IP isn't changing anytime soon, and when it changes (as it
 *** did with IPv6), these different systems all implemented it slightly
 *** differently, and that caused a lot of problems for us.
 *** So the BE13 API has a single implementation and it's good enough
 *** for our uses.
 ***/

namespace be13 {

#ifndef ETH_ALEN
#  define ETH_ALEN 6                    // ethernet address len
#endif

#ifndef IPPROTO_TCP
#  define IPPROTO_TCP     6               /* tcp */
#endif

    struct ether_addr {
        uint8_t ether_addr_octet[ETH_ALEN];
    } __attribute__ ((__packed__));

    /* 10Mb/s ethernet header */
    struct ether_header {
        uint8_t  ether_dhost[ETH_ALEN]; /* destination eth addr */
        uint8_t  ether_shost[ETH_ALEN]; /* source ether addr    */
        uint16_t ether_type;            /* packet type ID field */
    } __attribute__ ((__packed__));

    /* The mess below is becuase these items are typedefs and
     * structs on some systems and #defines on other systems
     * So in the interest of portability we need to define *new*
     * structures that are only used here
     */

    typedef uint32_t ip4_addr_t;         // historical

    // on windows we use the definition that's in winsock
    struct ip4_addr {   
        ip4_addr_t addr;
    };

    /*
     * Structure of an internet header, naked of options.
     */
    struct ip4 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t ip_hl:4;                /* header length */
        uint8_t ip_v:4;                 /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
        uint8_t ip_v:4;                 /* version */
        uint8_t ip_hl:4;                /* header length */
#endif
        uint8_t  ip_tos;                /* type of service */
        uint16_t ip_len;                /* total length */
        uint16_t ip_id;                 /* identification */
        uint16_t ip_off;                /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        uint8_t ip_ttl;                 /* time to live */
        uint8_t ip_p;                   /* protocol */
        uint16_t ip_sum;                        /* checksum */
        struct ip4_addr ip_src, ip_dst; /* source and dest address */
    } __attribute__ ((__packed__));

    struct ip4_dgram {
        const struct ip4 *header;
        const uint8_t *payload;
        uint16_t payload_len;
    };

    /*
     * IPv6 header structure
     */
    struct ip6_addr {           // our own private ipv6 definition
        union {
            uint8_t   addr8[16];        // three ways to get the data
            uint16_t  addr16[8];
            uint32_t  addr32[4];
        } addr;                    /* 128-bit IP6 address */
    };
    struct ip6_hdr {
        union {
            struct ip6_hdrctl {
                uint32_t ip6_un1_flow;  /* 20 bits of flow-ID */
                uint16_t ip6_un1_plen;  /* payload length */
                uint8_t  ip6_un1_nxt;   /* next header */
                uint8_t  ip6_un1_hlim;  /* hop limit */
            } ip6_un1;
            uint8_t ip6_un2_vfc;        /* 4 bits version, top 4 bits class */
        } ip6_ctlun;
        struct ip6_addr ip6_src;        /* source address */
        struct ip6_addr ip6_dst;        /* destination address */
    } __attribute__((__packed__));

    struct ip6_dgram {
        const struct ip6_hdr *header;
        const uint8_t *payload;
        uint16_t payload_len;
    };

    /*
     * TCP header.
     * Per RFC 793, September, 1981.
     */
    typedef     uint32_t tcp_seq;
    struct tcphdr {
        uint16_t th_sport;              /* source port */
        uint16_t th_dport;              /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t th_x2:4;                /* (unused) */
        uint8_t th_off:4;               /* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
        uint8_t th_off:4;               /* data offset */
        uint8_t th_x2:4;                /* (unused) */
#  endif
        uint8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    uint16_t th_win;            /* window */
    uint16_t th_sum;            /* checksum */
    uint16_t th_urp;            /* urgent pointer */
};
/*
 * The packet_info structure records packets after they are read from the pcap library.
 * It preserves the original pcap information and information decoded from the MAC and
 * VLAN (IEEE 802.1Q) layers, as well as information that might be present from 802.11
 * interfaces. However it does not preserve the full radiotap information. 
 * 
 * packet_info is created to make it easier to write network forensic software. It encapsulates
 * much of the common knowledge needed to operate on packet-based IP networks.
 *
 * @param ts   - the actual packet time to use (adjusted)
 * @param pcap_data - Original data offset point from pcap
 * @param data - the actual packet data, minus the MAC layer
 * @param datalen - How much data is available at the datalen pointer
 * 
 */
class packet_info {
public:
    // IPv4 header offsets
    static const size_t ip4_proto_off = 9;
    static const size_t ip4_src_off = 12;
    static const size_t ip4_dst_off = 16;
    // IPv6 header offsets
    static const size_t ip6_nxt_hdr_off = 6;
    static const size_t ip6_plen_off = 4;
    static const size_t ip6_src_off = 8;
    static const size_t ip6_dst_off = 24;
    // TCP header offsets
    static const size_t tcp_sport_off = 0;
    static const size_t tcp_dport_off = 2;

    class frame_too_short : public std::logic_error {
    public:
        frame_too_short() :
            std::logic_error("frame too short to contain requisite network structures") {}
    };

    enum vlan_t {NO_VLAN=-1};
    /** create a packet, usually an IP packet.
     * @param d - start of MAC packet
     * @param d2 - start of IP data
     */
    packet_info(const int dlt,const struct pcap_pkthdr *h,const u_char *d,
                const struct timeval &ts_,const uint8_t *d2,size_t dl2):
        pcap_dlt(dlt),pcap_hdr(h),pcap_data(d),ts(ts_),ip_data(d2),ip_datalen(dl2){}
    packet_info(const int dlt,const struct pcap_pkthdr *h,const u_char *d):
        pcap_dlt(dlt),pcap_hdr(h),pcap_data(d),ts(h->ts),ip_data(d),ip_datalen(h->caplen){}

    const int    pcap_dlt;              // data link type; needed by libpcap, not provided
    const struct pcap_pkthdr *pcap_hdr; // provided by libpcap
    const u_char *pcap_data;            // provided by libpcap; where the MAC layer begins
    const struct timeval &ts;           // when packet received; possibly modified before packet_info created
    const uint8_t *const ip_data;       // pointer to where ip data begins
    const size_t ip_datalen;            // length of ip data

    static u_short nshort(const u_char *buf,size_t pos);   // return a network byte order short at offset pos
    int     ip_version() const;         // returns 4, 6 or 0
    u_short ether_type() const;         // returns 0 if not IEEE802, otherwise returns ether_type
    int     vlan() const;               // returns NO_VLAN if not IEEE802 or not VLAN, othererwise VID
    const uint8_t *get_ether_dhost() const;   // returns a pointer to ether dhost if ether packet
    const uint8_t *get_ether_shost() const;   // returns a pointer to ether shost if ether packet

    // packet typing
    bool    is_ip4() const;
    bool    is_ip6() const;
    bool    is_ip4_tcp() const;
    bool    is_ip6_tcp() const;
    // packet extraction
    // IPv4 - return pointers to fields or throws frame_too_short exception
    const struct in_addr *get_ip4_src() const;
    const struct in_addr *get_ip4_dst() const;
    uint8_t get_ip4_proto() const;
    // IPv6
    uint8_t  get_ip6_nxt_hdr() const;
    uint16_t get_ip6_plen() const;
    const struct ip6_addr *get_ip6_src() const;
    const struct ip6_addr *get_ip6_dst() const;
    // TCP
    uint16_t get_ip4_tcp_sport() const;
    uint16_t get_ip4_tcp_dport() const;
    uint16_t get_ip6_tcp_sport() const;
    uint16_t get_ip6_tcp_dport() const;
};

#ifdef DLT_IEEE802
    inline u_short packet_info::ether_type() const
    {
        if(pcap_dlt==DLT_IEEE802 || pcap_dlt==DLT_EN10MB){
            const struct ether_header *eth_header = (struct ether_header *) pcap_data;
            return ntohs(eth_header->ether_type);
        }
        return 0;
    }
#endif
    
#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */
#endif

#ifndef ETHERTYPE_SPRITE
#define ETHERTYPE_SPRITE        0x0500          /* Sprite */
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800          /* IP */
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806          /* Address resolution */
#endif

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */
#endif

#ifndef ETHERTYPE_AT
#define ETHERTYPE_AT            0x809B          /* AppleTalk protocol */
#endif

#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP          0x80F3          /* AppleTalk ARP */
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100          /* IEEE 802.1Q VLAN tagging */
#endif

#ifndef ETHERTYPE_IPX
#define ETHERTYPE_IPX           0x8137          /* IPX */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6          0x86dd          /* IP protocol version 6 */
#endif

#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK      0x9000          /* used to test interfaces */
#endif

    
    inline u_short packet_info::nshort(const u_char *buf,size_t pos) 
    {
        return (buf[pos]<<8) | (buf[pos+1]);
    }

    inline int packet_info::vlan() const
    {
        if(ether_type()==ETHERTYPE_VLAN){
            return nshort(pcap_data,sizeof(struct ether_header));
        }
        return -1;
    }
    
    inline int packet_info::ip_version() const
    {
        /* This takes advantage of the fact that ip4 and ip6 put the version number in the same place */
        if (ip_datalen >= sizeof(struct ip4)) {
            const struct ip4 *ip_header = (struct ip4 *) ip_data;
            switch(ip_header->ip_v){
            case 4: return 4;
            case 6: return 6;
            }
        }
        return 0;
    }

    // packet typing

    inline bool packet_info::is_ip4() const
    {
        return ip_version() == 4;
    }

    inline bool packet_info::is_ip6() const
    {
        return ip_version() == 6;
    }

    inline bool packet_info::is_ip4_tcp() const
    {
        if(ip_datalen < sizeof(struct ip4) + sizeof(struct tcphdr)) {
            return false;
        }
        return *((uint8_t*) (ip_data + ip4_proto_off)) == IPPROTO_TCP;
        return false;
    }

    inline bool packet_info::is_ip6_tcp() const
    {
        if(ip_datalen < sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
            return false;
        }
        return *((uint8_t*) (ip_data + ip6_nxt_hdr_off)) == IPPROTO_TCP;
    }

    // packet extraction
    // precondition: the apropriate packet type function must return true before using these functions.
    //     example: is_ip4_tcp() must return true before calling get_ip4_tcp_sport()

    // Get ether addresses; should this handle vlan and such?
    inline const uint8_t *packet_info::get_ether_dhost() const
    {
        if(pcap_hdr->caplen < sizeof(struct ether_addr)){
            throw new frame_too_short();
        }
        return ((const struct ether_header *)pcap_data)->ether_dhost;
    }

    inline const uint8_t *packet_info::get_ether_shost() const
    {
        if(pcap_hdr->caplen < sizeof(struct ether_addr)){
            throw new frame_too_short();
        }
        return ((const struct ether_header *)pcap_data)->ether_shost;
    }

    // IPv4
#  ifdef HAVE_DIAGNOSTIC_CAST_ALIGN
#    pragma GCC diagnostic ignored "-Wcast-align"
#  endif
    inline const struct in_addr *packet_info::get_ip4_src() const
    {
        if(ip_datalen < sizeof(struct ip4)) {
            throw new frame_too_short();
        }
        return (const struct in_addr *) ip_data + ip4_src_off;
    }
    inline const struct in_addr *packet_info::get_ip4_dst() const
    {
        if(ip_datalen < sizeof(struct ip4)) {
            throw new frame_too_short();
        }
        return (const struct in_addr *) ip_data + ip4_dst_off;
    }
#  ifdef HAVE_DIAGNOSTIC_CAST_ALIGN
#    pragma GCC diagnostic warning "-Wcast-align"
#  endif
    inline uint8_t packet_info::get_ip4_proto() const
    {
        if(ip_datalen < sizeof(struct ip4)) {
            throw new frame_too_short();
        }
        return *((uint8_t *) (ip_data + ip4_proto_off));
    }
    // IPv6
    inline uint8_t packet_info::get_ip6_nxt_hdr() const
    {
        if(ip_datalen < sizeof(struct ip6_hdr)) {
            throw new frame_too_short();
        }
        return *((uint8_t *) (ip_data + ip6_nxt_hdr_off));
    }
    inline uint16_t packet_info::get_ip6_plen() const
    {
        if(ip_datalen < sizeof(struct ip6_hdr)) {
            throw new frame_too_short();
        }
        //return ntohs(*((uint16_t *) (ip_data + ip6_plen_off)));
        return nshort(ip_data,ip6_plen_off);
    }
#  ifdef HAVE_DIAGNOSTIC_CAST_ALIGN
#    pragma GCC diagnostic ignored "-Wcast-align"
#  endif
    inline const struct ip6_addr *packet_info::get_ip6_src() const
    {
        if(ip_datalen < sizeof(struct ip6_hdr)) {
            throw new frame_too_short();
        }
        return (const struct ip6_addr *) ip_data + ip6_src_off;
    }
    inline const struct ip6_addr *packet_info::get_ip6_dst() const
    {
        if(ip_datalen < sizeof(struct ip6_hdr)) {
            throw new frame_too_short();
        }
        return (const struct ip6_addr *) ip_data + ip6_dst_off;
    }
#  ifdef HAVE_DIAGNOSTIC_CAST_ALIGN
#    pragma GCC diagnostic warning "-Wcast-align"
#  endif

    // TCP
    inline uint16_t packet_info::get_ip4_tcp_sport() const
    {
        if(ip_datalen < sizeof(struct tcphdr) + sizeof(struct ip4)) {
            throw new frame_too_short();
        }
        //return ntohs(*((uint16_t *) (ip_data + sizeof(struct ip4) + tcp_sport_off)));
        return nshort(ip_data,sizeof(struct ip4) + tcp_sport_off);
    }
    inline uint16_t packet_info::get_ip4_tcp_dport() const
    {
        if(ip_datalen < sizeof(struct tcphdr) + sizeof(struct ip4)) {
            throw new frame_too_short();
        }
        //return ntohs(*((uint16_t *) (ip_data + sizeof(struct ip4) + tcp_dport_off)));
        return nshort(ip_data,sizeof(struct ip4) + tcp_dport_off); // 

    }
    inline uint16_t packet_info::get_ip6_tcp_sport() const
    {
        if(ip_datalen < sizeof(struct tcphdr) + sizeof(struct ip6_hdr)) {
            throw new frame_too_short();
        }
        //return ntohs(*((uint16_t *) (ip_data + sizeof(struct ip6_hdr) + tcp_sport_off)));
        return nshort(ip_data,sizeof(struct ip6_hdr) + tcp_sport_off); // 
    }
    inline uint16_t packet_info::get_ip6_tcp_dport() const
    {
        if(ip_datalen < sizeof(struct tcphdr) + sizeof(struct ip6_hdr)) {
            throw new frame_too_short();
        }
        //return ntohs(*((uint16_t *) (ip_data + sizeof(struct ip6_hdr) + tcp_dport_off)));
        return nshort(ip_data,sizeof(struct ip6_hdr) + tcp_dport_off); // 
    }
};


typedef void scanner_t(const class scanner_params &sp,const class recursion_control_block &rcb);
typedef void process_t(const class scanner_params &sp); 
typedef void packet_callback_t(void *user,const be13::packet_info &pi);
    
/** scanner_info gets filled in by the scanner to tell the caller about the scanner.
 *
 */
class scanner_info {
private:
    static std::stringstream helpstream; // where scanner info help messages are saved.

    // default copy construction and assignment are meaningless
    // and not implemented
    scanner_info(const scanner_info &i);
    scanner_info &operator=(const scanner_info &i);
 public:
    static std::string helpstr(){return helpstream.str();}
    typedef std::map<std::string,std::string>  config_t; // configuration for scanner passed in

    /* scanner flags */
    static const int SCANNER_DISABLED       = 0x001; // v1: enabled by default 
    static const int SCANNER_NO_USAGE       = 0x002; // v1: do not show scanner in usage 
    static const int SCANNER_NO_ALL         = 0x004; // v2: do not enable with -eall 
    static const int SCANNER_FIND_SCANNER   = 0x008; // v2: this scanner uses the find_list 
    static const int SCANNER_RECURSE        = 0x010; // v3: this scanner will recurse
    static const int SCANNER_RECURSE_EXPAND = 0x020; // v3: recurses AND result is >= original size
    static const int SCANNER_WANTS_NGRAMS   = 0x040; // v3: Scanner gets buffers that are constant n-grams
    static const int SCANNER_FAST_FIND      = 0x080; // v3: This scanner is a very fast FIND scanner
    static const int SCANNER_DEPTH_0        = 0x100; // v3: scanner only runs at depth 0 by default
    static const int CURRENT_SI_VERSION     = 4;     

    static const std::string flag_to_string(const int flag){
        std::string ret;
        if(flag==0) ret += "NONE ";
        if(flag & SCANNER_DISABLED) ret += "SCANNER_DISABLED ";
        if(flag & SCANNER_NO_USAGE) ret += "SCANNER_NO_USAGE ";
        if(flag & SCANNER_NO_ALL) ret += "SCANNER_NO_ALL ";
        if(flag & SCANNER_FIND_SCANNER) ret += "SCANNER_FIND_SCANNER ";
        if(flag & SCANNER_RECURSE) ret += "SCANNER_RECURSE ";
        if(flag & SCANNER_RECURSE_EXPAND) ret += "SCANNER_RECURSE_EXPAND ";
        if(flag & SCANNER_WANTS_NGRAMS) ret += "SCANNER_WANTS_NGRAMS ";
        return ret;
    }

    /* Global config is passed to each scanner as a pointer when it is loaded.
     * Scanner histograms are added to 'histograms' by machinery.
     */
    struct scanner_config {
        scanner_config():namevals(),debug(){};
        virtual ~scanner_config(){}
        config_t  namevals;             // v3: (input) name=val map
        int       debug;                // v3: (input) current debug level
    };

    // never change the order or delete old fields, or else you will
    // break backwards compatability 
    scanner_info():si_version(CURRENT_SI_VERSION),
                   name(),author(),description(),url(),scanner_version(),flags(0),feature_names(),
                   histogram_defs(),packet_user(),packet_cb(),config(){}
    /* PASSED FROM SCANNER to API: */
    int         si_version;             // version number for this structure
    std::string      name;                   // v1: (output) scanner name
    std::string      author;                 // v1: (output) who wrote me?
    std::string      description;            // v1: (output) what do I do?
    std::string      url;                    // v1: (output) where I come from
    std::string      scanner_version;        // v1: (output) version for the scanner
    uint64_t    flags;                  // v1: (output) flags
    std::set<std::string> feature_names;          // v1: (output) features I need
    histogram_defs_t histogram_defs;        // v1: (output) histogram definition info
    void        *packet_user;           // v2: (output) data for network callback
    packet_callback_t *packet_cb;       // v2: (output) callback for processing network packets, or NULL

    /* PASSED FROM API TO SCANNER; access with functions below */
    const scanner_config *config;       // v3: (intput to scanner) config

    // These methods are implemented in the plugin system for the scanner to get config information.
    // The get_config methods should be called on the si object during PHASE_STARTUP
    virtual void get_config(const scanner_info::config_t &c,
                            const std::string &name,std::string *val,const std::string &help);
    virtual void get_config(const std::string &name,std::string *val,const std::string &help);
    virtual void get_config(const std::string &name,uint64_t *val,const std::string &help);
    virtual void get_config(const std::string &name,int32_t *val,const std::string &help);
    virtual void get_config(const std::string &name,uint32_t *val,const std::string &help);
    virtual void get_config(const std::string &name,uint16_t *val,const std::string &help);
    virtual void get_config(const std::string &name,uint8_t *val,const std::string &help);
#ifdef __APPLE__
    virtual void get_config(const std::string &name,size_t *val,const std::string &help);
#define HAVE_GET_CONFIG_SIZE_T
#endif
    virtual void get_config(const std::string &name,bool *val,const std::string &help);
    virtual ~scanner_info(){};
};
#include <map>
/**
 * The scanner_params class is a way for sending the scanner parameters
 * for this particular sbuf to be scanned.
 */

class scanner_params {
 public:
    enum print_mode_t {MODE_NONE=0,MODE_HEX,MODE_RAW,MODE_HTTP};
    static const int CURRENT_SP_VERSION=3;

    typedef std::map<std::string,std::string> PrintOptions;
    static print_mode_t getPrintMode(const PrintOptions &po){
        PrintOptions::const_iterator p = po.find("print_mode_t");
        if(p != po.end()){
            if(p->second=="MODE_NONE") return MODE_NONE;
            if(p->second=="MODE_HEX") return MODE_HEX;
            if(p->second=="MODE_RAW") return MODE_RAW;
            if(p->second=="MODE_HTTP") return MODE_HTTP;
        }
        return MODE_NONE;
    }
    static void setPrintMode(PrintOptions &po,int mode){
        switch(mode){
        default:
        case MODE_NONE:po["print_mode_t"]="MODE_NONE";return;
        case MODE_HEX:po["print_mode_t"]="MODE_HEX";return;
        case MODE_RAW:po["print_mode_t"]="MODE_RAW";return;
        case MODE_HTTP:po["print_mode_t"]="MODE_HTTP";return;
        }
    }

    // phase_t specifies when the scanner is being called
    typedef enum {
        PHASE_NONE     = -1,
        PHASE_STARTUP  = 0,            // called in main thread when scanner loads; called on EVERY scanner (called for help)
        PHASE_INIT     = 3,            // called in main thread for every ENABLED scanner after all scanners loaded
        PHASE_THREAD_BEFORE_SCAN = 4,  // called in worker thread for every ENABLED scanner before first scan
        PHASE_SCAN     = 1,            // called in worker thread for every ENABLED scanner to scan an sbuf
        PHASE_SHUTDOWN = 2,            // called in main thread for every ENABLED scanner when scanner is shutdown
    } phase_t ;
    static PrintOptions no_options;    // in common.cpp

    /********************
     *** CONSTRUCTORS ***
     ********************/

    /* A scanner params with all of the instance variables, typically for scanning  */
    scanner_params(phase_t phase_,const sbuf_t &sbuf_,class feature_recorder_set &fs_,
                   PrintOptions &print_options_):
        sp_version(CURRENT_SP_VERSION),
        phase(phase_),sbuf(sbuf_),fs(fs_),depth(0),print_options(print_options_),info(0),sxml(0){
    }

    /* A scanner params with no print options */
    scanner_params(phase_t phase_,const sbuf_t &sbuf_, class feature_recorder_set &fs_):
        sp_version(CURRENT_SP_VERSION),
        phase(phase_),sbuf(sbuf_),fs(fs_),depth(0),print_options(no_options),info(0),sxml(0){
    }

    /* A scanner params with no print options but an xmlstream */
    scanner_params(phase_t phase_,const sbuf_t &sbuf_,class feature_recorder_set &fs_,std::stringstream *xmladd):
        sp_version(CURRENT_SP_VERSION),
        phase(phase_),sbuf(sbuf_),fs(fs_),depth(0),print_options(no_options),info(0),sxml(xmladd){
    }

    /** Construct a scanner_params for recursion from an existing sp and a new sbuf.
     * Defaults to phase1
     */
    scanner_params(const scanner_params &sp_existing,const sbuf_t &sbuf_new):
        sp_version(CURRENT_SP_VERSION),phase(sp_existing.phase),
        sbuf(sbuf_new),fs(sp_existing.fs),depth(sp_existing.depth+1),
        print_options(sp_existing.print_options),info(sp_existing.info),sxml(0){
        assert(sp_existing.sp_version==CURRENT_SP_VERSION);
    };

    /**
     * A scanner params with an empty info
     */

    /**************************
     *** INSTANCE VARIABLES ***
     **************************/

    const int                   sp_version;                /* version number of this structure */
    const phase_t               phase;                 /* v1: 0=startup, 1=normal, 2=shutdown (changed to phase_t in v1.3) */
    const sbuf_t                &sbuf;                 /* v1: what to scan / only valid in SCAN_PHASE */
    class feature_recorder_set  &fs;     /* v1: where to put the results / only valid in SCAN_PHASE */
    const uint32_t              depth;            /* v1: how far down are we? / only valid in SCAN_PHASE */

    PrintOptions                &print_options;    /* v1: how to print / NOT USED IN SCANNERS */
    scanner_info                *info;             /* v2: set/get parameters on startup, hasher */
    std::stringstream           *sxml;         /* v3: on scanning and shutdown: CDATA added to XML stream (advanced feature) */
};


inline std::ostream & operator <<(std::ostream &os,const class scanner_params &sp){
    os << "scanner_params(" << sp.sbuf << ")";
    return os;
};

class recursion_control_block {
 public:
/**
 * @param callback_ - the function to call back
 * @param partName_ - the part of the forensic path processed by this scanner.
 */
    recursion_control_block(process_t *callback_,std::string partName_):
        callback(callback_),partName(partName_){}
    process_t *callback;
    std::string partName;            /* eg "ZIP", "GZIP" */
};
    
/* plugin.cpp. This will become a class...  */
class scanner_def {
public:;
    static uint32_t max_depth;          // maximum depth to scan for the scanners
    static uint32_t max_ngram;          // maximum ngram size to change
    scanner_def():scanner(0),enabled(false),info(),pathPrefix(){};
    scanner_t  *scanner;                // pointer to the primary entry point
    bool        enabled;                // is enabled?
    scanner_info info;                  // info block sent to and returned by scanner
    std::string      pathPrefix;             /* path prefix for recursive scanners */
};

namespace be13 {
    /* plugin.cpp */

    struct plugin {
        typedef std::vector<scanner_def *> scanner_vector;
        static scanner_vector current_scanners;                         // current scanners
        static bool dup_data_alerts;  // notify when duplicate data is not processed
        static uint64_t dup_data_encountered; // amount of dup data encountered

        static void set_scanner_debug(int debug);

        static void load_scanner(scanner_t scanner,const scanner_info::scanner_config &sc); // load a specific scanner
        static void load_scanner_file(std::string fn,const scanner_info::scanner_config &sc);    // load a scanner from a file
        static void load_scanners(scanner_t * const *scanners_builtin,const scanner_info::scanner_config &sc); // load the scan_ plugins
        static void load_scanner_directory(const std::string &dirname,const scanner_info::scanner_config &sc); // load scanners in the directory
        static void load_scanner_directories(const std::vector<std::string> &dirnames,const scanner_info::scanner_config &sc);
        static void load_scanner_packet_handlers();
        
        // send every enabled scanner the phase message
        static void message_enabled_scanners(scanner_params::phase_t phase,feature_recorder_set &fs);

        // returns the named scanner, or 0 if no scanner of that name
        static scanner_t *find_scanner(const std::string &name); 
        static void get_enabled_scanners(std::vector<std::string> &svector); // put the enabled scanners into the vector
        static void add_enabled_scanner_histograms_to_feature_recorder_set(feature_recorder_set &fs); 
        static bool find_scanner_enabled(); // return true if a find scanner is enabled
        
        // print info about the scanners:
        static void scanners_disable_all();                    // saves a command to disable all
        static void scanners_enable_all();                    // enable all of them
        static void set_scanner_enabled(const std::string &name,bool enable);
        static void set_scanner_enabled_all(bool enable);
        static void scanners_enable(const std::string &name); // saves a command to enable this scanner
        static void scanners_disable(const std::string &name); // saves a command to disable this scanner
        static void scanners_process_enable_disable_commands();               // process the enable/disable and config commands
        static void scanners_init(feature_recorder_set &fs); // init the scanners

        static void info_scanners(bool detailed_info,
                                  bool detailed_settings,
                                  scanner_t * const *scanners_builtin,const char enable_opt,const char disable_opt);
        

        /* Run the phases on the scanners */
        static void phase_shutdown(feature_recorder_set &fs,std::stringstream *sxml=0); // sxml is where to put XML from scanners that shutdown
        static uint32_t get_max_depth_seen();
        static void process_sbuf(const class scanner_params &sp);                              /* process for feature extraction */
        static void process_packet(const be13::packet_info &pi);

        /* recorders */
        static void get_scanner_feature_file_names(feature_file_names_t &feature_file_names);

    };
};

inline std::string itos(int i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string dtos(double d){ std::stringstream ss; ss << d;return ss.str();}
inline std::string utos(unsigned int i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string utos(uint64_t i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string utos(uint16_t i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string safe_utf16to8(std::wstring s){ // needs to be cleaned up
    std::string utf8_line;
    try {
        utf8::utf16to8(s.begin(),s.end(),back_inserter(utf8_line));
    } catch(utf8::invalid_utf16){
        /* Exception thrown: bad UTF16 encoding */
        utf8_line = "";
    }
    return utf8_line;
}

inline std::wstring safe_utf8to16(std::string s){ // needs to be cleaned up
    std::wstring utf16_line;
    try {
        utf8::utf8to16(s.begin(),s.end(),back_inserter(utf16_line));
    } catch(utf8::invalid_utf8){
        /* Exception thrown: bad UTF16 encoding */
        utf16_line = L"";
    }
    return utf16_line;
}

// truncate string at the matching char
inline void truncate_at(std::string &line, char ch) {
    size_t pos = line.find(ch);
    if(pos != std::string::npos) line.resize(pos);
}

#ifndef HAVE_ISXDIGIT
inline int isxdigit(int c)
{
    return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');
}
#endif

/* Useful functions for scanners */
#define ONE_HUNDRED_NANO_SEC_TO_SECONDS 10000000
#define SECONDS_BETWEEN_WIN32_EPOCH_AND_UNIX_EPOCH 11644473600LL
/*
 * 11644473600 is the number of seconds between the Win32 epoch
 * and the Unix epoch.
 *
 * http://arstechnica.com/civis/viewtopic.php?f=20&t=111992
 * gmtime_r() is Linux-specific. You'll find a copy in util.cpp for Windows.
 */

inline std::string microsoftDateToISODate(const uint64_t &time)
{
    time_t tmp = (time / ONE_HUNDRED_NANO_SEC_TO_SECONDS) - SECONDS_BETWEEN_WIN32_EPOCH_AND_UNIX_EPOCH;
    
    struct tm time_tm;
    gmtime_r(&tmp, &time_tm);
    char buf[256];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &time_tm); // Zulu time
    return std::string(buf);
}

/* Convert Unix timestamp to ISO format */
inline std::string unixTimeToISODate(const uint64_t &t)
{
    struct tm time_tm;
    time_t tmp=t;
    gmtime_r(&tmp, &time_tm);
    char buf[256];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &time_tm); // Zulu time
    return std::string(buf);
}

/* Many internal windows and Linux structures require a valid printable name in ASCII */
inline bool validASCIIName(const std::string &name)
{
    for(size_t i = 0; i< name.size(); i++){
        if(((u_char)name[i]) & 0x80) return false; // high bit should not be set
        if(((u_char)name[i]) < ' ') return false;  // should not be control character
        if(((u_char)name[i]) == 0x7f) return false; // DEL is not printable
    }
    return true;
}

#endif
