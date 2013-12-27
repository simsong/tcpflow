/**
 * Include this header in applications using wifipcap.
 * Released under GPLv3.
 * Some code (c) Jeffrey Pang <jeffpang@cs.cmu.edu>, 2003
 *           (C) Simson Garfinkel <simsong@acm.org> 2012-
 */

#ifndef _WIFIPCAP_H_
#define _WIFIPCAP_H_

#include <list>
#include <stdint.h>
#include <inttypes.h>

#include <pcap/pcap.h>
#include <netinet/in.h>

#include "arp.h"
#include "ip.h"
#include "ip6.h"
#include "tcp.h"
#include "udp.h"
#include "TimeVal.h"

/* Lengths of 802.11 header components. */
#define	IEEE802_11_FC_LEN		2
#define	IEEE802_11_DUR_LEN		2
#define	IEEE802_11_DA_LEN		6
#define	IEEE802_11_SA_LEN		6
#define	IEEE802_11_BSSID_LEN		6
#define	IEEE802_11_RA_LEN		6
#define	IEEE802_11_TA_LEN		6
#define	IEEE802_11_SEQ_LEN		2
#define	IEEE802_11_IV_LEN		3
#define	IEEE802_11_KID_LEN		1

/* Frame check sequence length. */
#define	IEEE802_11_FCS_LEN		4

/* Lengths of beacon components. */
#define	IEEE802_11_TSTAMP_LEN		8
#define	IEEE802_11_BCNINT_LEN		2
#define	IEEE802_11_CAPINFO_LEN		2
#define	IEEE802_11_LISTENINT_LEN	2

#define	IEEE802_11_AID_LEN		2
#define	IEEE802_11_STATUS_LEN		2
#define	IEEE802_11_REASON_LEN		2

/* Length of previous AP in reassocation frame */
#define	IEEE802_11_AP_LEN		6

#define	T_MGMT 0x0		/* management */
#define	T_CTRL 0x1		/* control */
#define	T_DATA 0x2		/* data */
#define	T_RESV 0x3		/* reserved */

#define	ST_ASSOC_REQUEST   	0x0
#define	ST_ASSOC_RESPONSE 	0x1
#define	ST_REASSOC_REQUEST   	0x2
#define	ST_REASSOC_RESPONSE  	0x3
#define	ST_PROBE_REQUEST   	0x4
#define	ST_PROBE_RESPONSE   	0x5
/* RESERVED 			0x6  */
/* RESERVED 			0x7  */
#define	ST_BEACON   		0x8
#define	ST_ATIM			0x9
#define	ST_DISASSOC		0xA
#define	ST_AUTH			0xB
#define	ST_DEAUTH		0xC
/* RESERVED 			0xD  */
/* RESERVED 			0xE  */
/* RESERVED 			0xF  */

#define	CTRL_PS_POLL            0xA
#define	CTRL_RTS                0xB
#define	CTRL_CTS                0xC
#define	CTRL_ACK                0xD
#define	CTRL_CF_END             0xE
#define	CTRL_END_ACK            0xF

#define	DATA_DATA		0x0
#define	DATA_DATA_CF_ACK	0x1
#define	DATA_DATA_CF_POLL	0x2
#define	DATA_DATA_CF_ACK_POLL	0x3
#define	DATA_NODATA		0x4
#define	DATA_NODATA_CF_ACK	0x5
#define	DATA_NODATA_CF_POLL	0x6
#define	DATA_NODATA_CF_ACK_POLL	0x7

/*
 * Bits in the frame control field.
 */
#define	FC_VERSION(fc)		((fc) & 0x3)
#define	FC_TYPE(fc)		(((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)		(((fc) >> 4) & 0xF)
#define	FC_TO_DS(fc)		((fc) & 0x0100)
#define	FC_FROM_DS(fc)		((fc) & 0x0200)
#define	FC_MORE_FLAG(fc)	((fc) & 0x0400)
#define	FC_RETRY(fc)		((fc) & 0x0800)
#define	FC_POWER_MGMT(fc)	((fc) & 0x1000)
#define	FC_MORE_DATA(fc)	((fc) & 0x2000)
#define	FC_WEP(fc)		((fc) & 0x4000)
#define	FC_ORDER(fc)		((fc) & 0x8000)

#define	MGMT_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+          \
			 IEEE802_11_DA_LEN+IEEE802_11_SA_LEN+           \
			 IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)

#define	CAPABILITY_ESS(cap)	((cap) & 0x0001)
#define	CAPABILITY_IBSS(cap)	((cap) & 0x0002)
#define	CAPABILITY_CFP(cap)	((cap) & 0x0004)
#define	CAPABILITY_CFP_REQ(cap)	((cap) & 0x0008)
#define	CAPABILITY_PRIVACY(cap)	((cap) & 0x0010)



struct MAC {          
    enum { PRINT_FMT_COLON, PRINT_FMT_PLAIN };
    uint64_t val;
    MAC():val() {}
    MAC(uint64_t val_):val(val_){}
    MAC(const MAC& o):val(o.val){}
    MAC(const uint8_t *ether):val(
        ((uint64_t)(ether[0]) << 40) |
        ((uint64_t)(ether[1]) << 32) |
        ((uint64_t)(ether[2]) << 24) |
        ((uint64_t)(ether[3]) << 16) |
        ((uint64_t)(ether[4]) <<  8) |
        ((uint64_t)(ether[5]) <<  0)){}
    MAC(const char *str):val(){
        int ether[6];
        int ret = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                         &ether[0], &ether[1], &ether[2], &ether[3], &ether[4], &ether[5]);
        if (ret != 6) {
            ret = sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
                         &ether[0], &ether[1], &ether[2], &ether[3], &ether[4], &ether[5]);
        }
        if (ret != 6) {
            std::cerr << "bad mac address: " << str << std::endl;
            val = 0;
            return;
        }
        val = 
            ((uint64_t)(ether[0]) << 40) |
            ((uint64_t)(ether[1]) << 32) |
            ((uint64_t)(ether[2]) << 24) |
            ((uint64_t)(ether[3]) << 16) |
            ((uint64_t)(ether[4]) <<  8) |
            ((uint64_t)(ether[5]) <<  0);
    }
    
    bool operator==(const MAC& o) const { return val == o.val; }
    bool operator!=(const MAC& o) const { return val != o.val; }
    bool operator<(const MAC& o)  const { return val <  o.val; }
    
    static MAC ether2MAC(const uint8_t * ether) {
        return MAC(ether);
    }

    static MAC broadcast;
    static MAC null;
    static int print_fmt;
};

typedef enum {
    NOT_PRESENT,
    PRESENT,
    TRUNCATED
} elem_status_t;

struct ssid_t {
    ssid_t():element_id(),length(),ssid(){};
    u_int8_t	element_id;
    u_int8_t	length;
    char	ssid[33];  /* 32 + 1 for null */
};

struct rates_t {
    rates_t():element_id(),length(),rate(){};
    u_int8_t	element_id;
    u_int8_t	length;
    u_int8_t	rate[16];
};

struct challenge_t {
    challenge_t():element_id(),length(),text(){};
    u_int8_t	element_id;
    u_int8_t	length;
    u_int8_t	text[254]; /* 1-253 + 1 for null */
};

struct fh_t {
    fh_t():element_id(),length(),dwell_time(),hop_set(),hop_pattern(),hop_index(){};
    u_int8_t	element_id;
    u_int8_t	length;
    u_int16_t	dwell_time;
    u_int8_t	hop_set;
    u_int8_t 	hop_pattern;
    u_int8_t	hop_index;
};

struct ds_t {
    u_int8_t	element_id;
    u_int8_t	length;
    u_int8_t	channel;
};

struct cf_t {
    u_int8_t	element_id;
    u_int8_t	length;
    u_int8_t	count;
    u_int8_t	period;
    u_int16_t	max_duration;
    u_int16_t	dur_remaing;
};

struct tim_t {
    u_int8_t	element_id;
    u_int8_t	length;
    u_int8_t	count;
    u_int8_t	period;
    u_int8_t	bitmap_control;
    u_int8_t	bitmap[251];
};

#define	E_SSID 		0
#define	E_RATES 	1
#define	E_FH	 	2
#define	E_DS 		3
#define	E_CF	 	4
#define	E_TIM	 	5
#define	E_IBSS 		6
/* reserved 		7 */
/* reserved 		8 */
/* reserved 		9 */
/* reserved 		10 */
/* reserved 		11 */
/* reserved 		12 */
/* reserved 		13 */
/* reserved 		14 */
/* reserved 		15 */
/* reserved 		16 */

#define	E_CHALLENGE 	16
/* reserved 		17 */
/* reserved 		18 */
/* reserved 		19 */
/* reserved 		16 */
/* reserved 		16 */

// XXX Jeff: no FCS fields are filled in right now

#define	CTRL_RTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+  \
			 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN)

struct ctrl_cts_t {
    ctrl_cts_t():fc(),duration(),ra(),fcs(){};
    u_int16_t fc;
    u_int16_t duration;
    MAC ra;
    u_int8_t fcs[4];
};

#define	CTRL_CTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ack_t {
    ctrl_ack_t():fc(),duration(),ra(),fcs(){};
    u_int16_t fc;
    u_int16_t duration;
    MAC ra;
    u_int8_t fcs[4];
};

#define	CTRL_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ps_poll_t {
    ctrl_ps_poll_t():fc(),aid(),bssid(),ta(),fcs(){};
    u_int16_t fc;
    u_int16_t aid;
    MAC bssid;
    MAC ta;
    u_int8_t fcs[4];
};

#define	CTRL_PS_POLL_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_AID_LEN+  \
				 IEEE802_11_BSSID_LEN+IEEE802_11_TA_LEN)

struct ctrl_end_t {
    ctrl_end_t():fc(),duration(),ra(),bssid(),fcs(){}
    u_int16_t fc;
    u_int16_t duration;
    MAC ra;
    MAC bssid;
    u_int8_t fcs[4];
};

#define	CTRL_END_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+          \
			 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

struct ctrl_end_ack_t {
    ctrl_end_ack_t():fc(),duration(),ra(),bssid(),fcs(){};
    u_int16_t fc;
    u_int16_t duration;
    MAC ra;
    MAC bssid;
    u_int8_t fcs[4];
};

#define	CTRL_END_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+  \
				 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)
#define	IV_IV(iv)	((iv) & 0xFFFFFF)
#define	IV_PAD(iv)	(((iv) >> 24) & 0x3F)
#define	IV_KEYID(iv)	(((iv) >> 30) & 0x03)

struct mac_hdr_t {                 // unified 80211 header
    mac_hdr_t():fc(),duration(),seq_ctl(),seq(),frag(),da(),sa(),ta(),ra(),bssid(),qos(){}
    uint16_t fc;                    // frame control
    uint16_t duration;
    uint16_t seq_ctl;
    uint16_t seq;                   // sequence number
    uint8_t frag;                   // fragment number?
    MAC da;                         // destination address // address1
    MAC sa;                         // source address      // address2
    MAC ta;                         // transmitter         // address3 
    MAC ra;                         // receiver            // address4
    MAC bssid;                      // BSSID
    bool qos;                       // has quality of service
};
        
#if 0
struct data_hdr_ibss_t {          // 80211 Independent Basic Service Set - e.g. ad hoc mode
    data_hdr_ibss_t():fc(),duration(),seq(),frag(),fcs(){};
    u_int16_t fc;
    u_int16_t duration;
    u_int16_t seq;
    u_int8_t  frag;
    u_int8_t  fcs[4];
};

struct data_hdr_t {
    data_hdr_t():fc(),duration(),seq(),frag(),sa(),da(),bssid(),fcs(){}
    u_int16_t fc;                   // 
    u_int16_t duration;             // ?
    u_int16_t seq;                  // sequence #?
    u_int8_t  frag;                 // fragment #?
    MAC       sa;                   // sender address
    MAC       da;                   // destination address
    MAC       bssid;                // base station ID
    u_int8_t  fcs[4];               // frame check sequence
};

struct data_hdr_wds_t {             // 80211 Wireless Distribution System
    data_hdr_wds_t():fc(),duration(),seq(),frag(),ra(),ta(),sa(),da(),fcs(){}
    u_int16_t fc;
    u_int16_t duration;
    u_int16_t seq;
    u_int8_t frag;
    MAC ra;
    MAC ta;
    MAC sa;
    MAC da;
    u_int8_t fcs[4];
};
#endif

#define	DATA_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+          \
			 IEEE802_11_SA_LEN+IEEE802_11_DA_LEN+           \
			 IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)

#define	DATA_WDS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+          \
			 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN+           \
			 IEEE802_11_SA_LEN+IEEE802_11_DA_LEN+IEEE802_11_SEQ_LEN)

/* Jeff: added for fully-decoded wep info */
struct wep_hdr_t {
    wep_hdr_t():iv(),pad(),keyid(){};
    u_int32_t iv;
    u_int32_t pad;
    u_int32_t keyid;
};

/* prism header */
#ifdef _WIN32
#pragma pack(push, 1)
#endif
struct prism2_pkthdr {
    uint32_t host_time;
    uint32_t mac_time;
    uint32_t channel;
    uint32_t rssi;
    uint32_t sq;
    int32_t  signal;
    int32_t  noise;
    uint32_t rate;
    uint32_t istx;
    uint32_t frmlen;
} __attribute__((__packed__));

struct radiotap_hdr {
    bool has_channel;
    int channel;
    bool has_fhss;
    int fhss_fhset;
    int fhss_fhpat;
    bool has_rate;
    int rate;
    bool has_signal_dbm;
    int signal_dbm;
    bool has_noise_dbm;
    int noise_dbm;
    bool has_signal_db;
    int signal_db;
    bool has_noise_db;
    int noise_db;
    bool has_quality;
    int quality;
    bool has_txattenuation;
    int txattenuation;
    bool has_txattenuation_db;
    int txattenuation_db;
    bool has_txpower_dbm;
    int txpower_dbm;
    bool has_flags;
    bool flags_cfp;
    bool flags_short_preamble;
    bool flags_wep;
    bool flags_fragmented;
    bool flags_badfcs;
    bool has_antenna;
    int antenna;
    
    bool has_tsft;
    u_int64_t tsft;

    bool has_rxflags;
    int rxflags;

    bool has_txflags;
    int txflags;

    bool has_rts_retries;
    int rts_retries;

    bool has_data_retries;
    int data_retries;
} __attribute__((__packed__));

struct ether_hdr_t {
    ether_hdr_t():sa(),da(),type(){};
    MAC sa, da;
    uint16_t type;
};

struct mgmt_header_t {
    mgmt_header_t():fc(),duration(),da(),sa(),bssid(),seq(),frag(){};
    u_int16_t fc;
    u_int16_t duration;
    MAC da;
    MAC sa;
    MAC bssid;
    u_int16_t seq;
    u_int8_t  frag;
};

struct mgmt_body_t {

    mgmt_body_t():timestamp(),beacon_interval(),listen_interval(),status_code(),aid(),ap(),reason_code(),
                  auth_alg(),auth_trans_seq_num(),challenge_status(),challenge(),capability_info(),
                  ssid_status(),ssid(),rates_status(),rates(),ds_status(),ds(),cf_status(),cf(),
                  fh_status(),fh(),tim_status(),tim(){};

    u_int8_t   	timestamp[IEEE802_11_TSTAMP_LEN];
    u_int16_t  	beacon_interval;
    u_int16_t 	listen_interval;
    u_int16_t 	status_code;
    u_int16_t 	aid;
    u_char		ap[IEEE802_11_AP_LEN];
    u_int16_t	reason_code;
    u_int16_t	auth_alg;
    u_int16_t	auth_trans_seq_num;
    elem_status_t	challenge_status;
    struct challenge_t  challenge;
    u_int16_t	capability_info;
    elem_status_t	ssid_status;
    struct ssid_t	ssid;
    elem_status_t	rates_status;
    struct rates_t 	rates;
    elem_status_t	ds_status;
    struct ds_t	ds;
    elem_status_t	cf_status;
    struct cf_t	cf;
    elem_status_t	fh_status;
    struct fh_t	fh;
    elem_status_t	tim_status;
    struct tim_t	tim;
};

struct ctrl_rts_t {
    ctrl_rts_t():fc(),duration(),ra(),ta(),fcs(){}
    u_int16_t fc;
    u_int16_t duration;
    MAC ra;
    MAC ta;
    u_int8_t fcs[4];
};

#ifdef _WIN32
#pragma pack(pop)
#endif



/**
 * Applications should implement a subclass of this interface and pass
 * it to Wifipcap::Run(). Each time pcap reads a packet, Wifipcap will
 * call:
 *
 * (1) PacketBegin()
 *
 * (2) Each Handle*() callback in order from layer 1 to layer 3 (or as
 *     far as it is able to demultiplex the packet). The time values 
 *     are the same in all these calls. The 'len' argument passed to
 *     functions refers to the amount of captured data available
 *     (e.g., in the 'rest' variable), not necessarily the original
 *     length of the packet (to get that, look inside appropriate
 *     packet headers, or during PacketBegin()).
 *
 * (3) PacketEnd()
 *
 * If the header for a layer was truncated, the appropriate function
 * will be called with the header == NULL and the rest == the start of
 * the packet.  For truncated 802.11 headers, 80211Unknown will be
 * called with fc == -1; for truncated ICMP headers, type == code ==
 * -1.
 *
 * All structures passed to the application will have fields in host
 * byte-order. For details about each header structure, see the
 * obvious header (e.g., ieee802_11.h for 802.11 stuff, ip.h for IPv4,
 * tcp.h for TCP, etc.). Note that there may be structures with
 * similar names that are only used internally; don't confuse them.
 *
 * For help parsing other protocols, the tcpdump source code will be
 * helpful. See the print-X.c file for help parsing protocol X.
 * The entry function is usually called X_print(...).
 */

struct WifiPacket;
struct WifipcapCallbacks;
class Wifipcap;
extern std::ostream& operator<<(std::ostream& out, const MAC& mac);
extern std::ostream& operator<<(std::ostream& out, const struct in_addr& ip);

///////////////////////////////////////////////////////////////////////////////


/* 
 * This class decodes a specific packet
 */
struct WifiPacket {
    /* Some instance variables */

    /** 48-bit MACs in 64-bit ints */
    static int debug;                   // prints callback before they are called

    WifiPacket(WifipcapCallbacks *cbs_,const int header_type_,const struct pcap_pkthdr *header_,const u_char *packet_):
        cbs(cbs_),header_type(header_type_),header(header_),packet(packet_),fcs_ok(false){}
    void parse_elements(struct mgmt_body_t *pbody, const u_char *p, int offset, size_t len);
    int handle_beacon(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_assoc_request(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_assoc_response(const struct mgmt_header_t *pmh, const u_char *p, size_t len, bool reassoc = false);
    int handle_reassoc_request(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_reassoc_response(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_probe_request(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_probe_response(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_atim(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_disassoc(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_auth(const struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int handle_deauth(const struct mgmt_header_t *pmh, const u_char *p, size_t len);

    int decode_mgmt_body(u_int16_t fc, struct mgmt_header_t *pmh, const u_char *p, size_t len);
    int decode_mgmt_frame(const u_char * ptr, size_t len, u_int16_t fc, u_int8_t hdrlen);
    int decode_data_frame(const u_char * ptr, size_t len, u_int16_t fc);
    int decode_ctrl_frame(const u_char * ptr, size_t len, u_int16_t fc);

    /* Handle the individual packet types based on DTL callback switch */
    void handle_llc(const mac_hdr_t &hdr,const u_char *ptr, size_t len,u_int16_t fc);
    void handle_wep(const u_char *ptr, size_t len);
    void handle_prism(const u_char *ptr, size_t len);
    void handle_ether(const u_char *ptr, size_t len);
    void handle_ip(const u_char *ptr, size_t len);
    void handle_80211(const u_char *ptr, size_t len); 
    int print_radiotap_field(struct cpack_state *s, u_int32_t bit, int *pad, radiotap_hdr *hdr);
    void handle_radiotap(const u_char *ptr, size_t caplen);

    /* And finally the data for each packet */
    WifipcapCallbacks *cbs;             // the callbacks to use with this packet
    const int header_type;                    // DLT
    const struct pcap_pkthdr *header;   // the actual pcap headers
    const u_char *packet;               // the actual packet data
    bool fcs_ok;                        // was it okay?
};


struct WifipcapCallbacks {
    /****************************************************************
     *** Data Structures for each Packet Follow
     ****************************************************************/

    WifipcapCallbacks(){};
    virtual ~WifipcapCallbacks(){};

    virtual const char *name() const {return "WifipcapCallbacks";} // override with your own name!

    /* Instance variables --- for a specific packet.
     * (Previously all of the functions had these parameters as the arguments, which made no sense)
     */
    /**
     * @param t the time the packet was captured
     * @param pkt the entire packet captured
     * @param len the length of the data captured
     * @param origlen the original length of the data (before truncated by pcap)
     */
    virtual void PacketBegin(const WifiPacket &p, const u_char *pkt, size_t len, int origlen){}
    virtual void PacketEnd(const WifiPacket &p ){}

    // If a Prism or RadioTap packet is found, call these, and then call Handle80211()

    virtual void HandlePrism(const WifiPacket &p, struct prism2_pkthdr *hdr, const u_char *rest, size_t len){}
    virtual void HandleRadiotap(const WifiPacket &p, struct radiotap_hdr *hdr, const u_char *rest, size_t len){}

    // 802.11 MAC (see ieee802_11.h)
    //
    // This method is called for every 802.11 frame just before the
    // specific functions below are called. This allows you to have
    // one entry point to easily do something with all 802.11 packets.
    //
    // The MAC addresses will be MAC::null unless applicable to the
    // particular type of packet. For unknown 802.11 packets, all
    // MAC addresses will be MAC::null and if the packet is truncated,
    // so that fc was not decoded, it will be 0.
    //
    // fcs_ok will be true if the frame had a valid fcs (frame
    // checksum) trailer and Check80211FCS() returns true.
    virtual void Handle80211(const WifiPacket &p, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta, const u_char *ptr, size_t len){}

    // if this returns true, we'll check the fcs on every frame.
    // Note: if frames are truncated, the fcs check will fail, so you need
    // a complete packet capture for this to be meaningful
    virtual bool Check80211FCS(const WifiPacket &p ) { return false; }

    // Management
    virtual void Handle80211MgmtBeacon(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body)   {puts("Handle80211MgmtBeacon");}
    virtual void Handle80211MgmtAssocRequest(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtAssocResponse(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtReassocRequest(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtReassocResponse(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtProbeRequest(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtProbeResponse(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtATIM(const WifiPacket &p, const struct mgmt_header_t *hdr){}
    virtual void Handle80211MgmtDisassoc(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtAuth(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}
    virtual void Handle80211MgmtAuthSharedKey(const WifiPacket &p, const struct mgmt_header_t *hdr, const u_char *rest, size_t len){}
    virtual void Handle80211MgmtDeauth(const WifiPacket &p, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body){}

    // Control
    virtual void Handle80211CtrlPSPoll(const WifiPacket &p, const struct ctrl_ps_poll_t *hdr){}
    virtual void Handle80211CtrlRTS(const WifiPacket &p, const struct ctrl_rts_t *hdr){}
    virtual void Handle80211CtrlCTS(const WifiPacket &p, const struct ctrl_cts_t *hdr){}
    virtual void Handle80211CtrlAck(const WifiPacket &p, const struct ctrl_ack_t *hdr){}
    virtual void Handle80211CtrlCFEnd(const WifiPacket &p, const struct ctrl_end_t *hdr){}
    virtual void Handle80211CtrlEndAck(const WifiPacket &p, const struct ctrl_end_ack_t *hdr){}
    
    // Data - Each data packet results in a call to Handle80211Data and one of the others
    virtual void Handle80211Data(const WifiPacket &p, u_int16_t fc, const struct mac_hdr_t &hdr,
                                 const u_char *rest, size_t len){}
    virtual void Handle80211DataIBSS(const WifiPacket &p, const struct mac_hdr_t &hdr, const u_char *rest, size_t len){}
    virtual void Handle80211DataFromAP(const WifiPacket &p, const struct mac_hdr_t &hdr, const u_char *rest, size_t len){}
    virtual void Handle80211DataToAP(const WifiPacket &p, const struct mac_hdr_t &hdr, const u_char *rest, size_t len){}
    virtual void Handle80211DataWDS(const WifiPacket &p, const struct mac_hdr_t &hdr, const u_char *rest, size_t len){}
    
    // Erroneous Frames/Truncated Frames
    // Also called if Check80211FCS() returns true and the checksum is bad
    virtual void Handle80211Unknown(const WifiPacket &p, int fc, const u_char *rest, size_t len){}

    // LLC/SNAP (const WifiPacket &p, see llc.h)

    virtual void HandleLLC(const WifiPacket &p, const struct llc_hdr_t *hdr, const u_char *rest, size_t len){}
    virtual void HandleLLCUnknown(const WifiPacket &p, const u_char *rest, size_t len){}
    virtual void HandleWEP(const WifiPacket &p, const struct wep_hdr_t *hdr, const u_char *rest, size_t len){}

    // for non-802.11 ethernet traces
    virtual void HandleEthernet(const WifiPacket &p, const struct ether_hdr_t *hdr, const u_char *rest, size_t len){}

    ///// Layer 2 (see arp.h, ip.h, ip6.h)

    virtual void HandleARP(const WifiPacket &p, const arp_pkthdr *hdr, const u_char *rest, size_t len){}
    virtual void HandleIP(const WifiPacket &p, const ip4_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, size_t len){}
    virtual void HandleIP6(const WifiPacket &p, const ip6_hdr_t *hdr, const u_char *rest, size_t len){}
    virtual void HandleL2Unknown(const WifiPacket &p, uint16_t ether_type, const u_char *rest, size_t len){}

    ///// Layer 3 (see icmp.h, tcp.h, udp.h)

    // IP headers are included for convenience. one of ip4h, ip6h will
    // be non-NULL. Only the first fragment in a fragmented packet
    // will be decoded. The other fragments will not be passed to any
    // of these functions.

    // Jeff: XXX icmp callback will probably eventually change to
    // parse the entire icmp packet
    virtual void HandleICMP(const WifiPacket &p, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, int type, int code, const u_char *rest, size_t len){}
    virtual void HandleTCP(const WifiPacket &p, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const tcp_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, size_t len){}
    virtual void HandleUDP(const WifiPacket &p, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const udp_hdr_t *hdr, const u_char *rest, size_t len){}
    virtual void HandleL3Unknown(const WifiPacket &p, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const u_char *rest, size_t len){}
};




/**
 * Applications create an instance of this to start processing a pcap
 * trace. Example:
 *
 *    Wifipcap *wp = new Wifipcap("/path/to/mytrace.cap");
 *    wp->Run(new MyCallbacks());
 */
class Wifipcap {
    // these are not implemented
    Wifipcap(const Wifipcap &t);
    Wifipcap &operator=(const Wifipcap &that);
public:
    /**
     * Utility functions for 802.11 fields.
     */
    class WifiUtil {
    public:
        // some functions to convert codes to ascii names
        static const char *MgmtAuthAlg2Txt(uint v);
        static const char *MgmtStatusCode2Txt(uint v);
        static const char *MgmtReasonCode2Txt(uint v);
        static const char *EtherType2Txt(uint t);
    };

    /**
     * Initialize the lib. Exits with error message upon failure.
     *
     * @param name the device if live = true, else the file name of
     * the trace. If the file name ends in '.gz', we assume its a
     * gzipped trace and will pipe it through zcat before parsing it.
     * @param live true if reading from a device, otherwise a trace
     */
    Wifipcap():descr(),datalink(),morefiles(),verbose(),startTime(),lastPrintTime(),packetsProcessed(){
    }; 
    Wifipcap(const char *name, bool live_ = false, bool verbose_ = false):
        descr(NULL), datalink(),morefiles(),verbose(verbose_), startTime(TIME_NONE), 
        lastPrintTime(TIME_NONE), packetsProcessed(0) {
        Init(name, live_);
    }
    
    /**
     * Initialize with nfiles. Will run on all of them in order.
     */
    Wifipcap(const char* const *names, int nfiles_, bool verbose_ = false):
        descr(NULL), datalink(),morefiles(),verbose(verbose_), startTime(TIME_NONE), 
        lastPrintTime(TIME_NONE), packetsProcessed(0) {
        for (int i=0; i<nfiles_; i++) {
            morefiles.push_back(names[i]);
        }
        InitNext();
    }

    virtual ~Wifipcap(){ };

    /**
     * Set a pcap filter. Returns non-null error string if fail.
     */
    const char *SetFilter(const char *filter);

    /**
     * Print some diagnostic messages if verbose
     */
    void SetVerbose(bool v = true) { verbose = v; }

    /**
     * Start executing the packet processing loop, calling back cbs as
     * required.
     *
     * @param cbs the callbacks to use during this run.
     * @param maxpkts the maximum number of packets to process before
     * returning. 0 = inifinite.
     */
    /** Packet handling callback
     *  @param user - pointer to a PcapUserData struct
     */

    /** Solely for call from ::handle_packet to WifiPcap::handle_packet */
    struct PcapUserData  {
        PcapUserData(class Wifipcap *wcap_,
                     struct WifipcapCallbacks *cbs_,const int header_type_):wcap(wcap_),cbs(cbs_),header_type(header_type_){};
        class Wifipcap *wcap;
        struct WifipcapCallbacks *cbs;
        const int header_type;
    };
    void dl_prism(const PcapUserData &data, const struct pcap_pkthdr *header, const u_char * packet);
    void dl_ieee802_11_radio(const PcapUserData &data, const struct pcap_pkthdr *header, const u_char * packet);
    void handle_packet(WifipcapCallbacks *cbs,int header_type,
                       const struct pcap_pkthdr *header, const u_char * packet);

    static void dl_prism(const u_char *user, const struct pcap_pkthdr *header, const u_char * packet);
    static void dl_ieee802_11_radio(const u_char *user, const struct pcap_pkthdr *header, const u_char * packet);
    static void handle_packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char * packet);

    pcap_t *GetPcap() const { return descr; }
    int    GetDataLink() const { return datalink; }
    void   Run(WifipcapCallbacks *cbs, int maxpkts = 0);

private:
    void  Init(const char *name, bool live);
    bool  InitNext();
    pcap_t *descr;                      // can't be const
    int   datalink;
    std::list<const char *> morefiles;

public:
    bool           verbose;
    struct timeval startTime;
    struct timeval lastPrintTime;
    uint64_t       packetsProcessed;
    static const int PRINT_TIME_INTERVAL = 6*60*60; // sec
};

///////////////////////////////////////////////////////////////////////////////

#include "ieee802_11_radio.h"
#include "llc.h"

#endif
