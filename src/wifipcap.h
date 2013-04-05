
/**
 * Include this header in applications using wifipcap.
 * Some code (c) Jeffrey Pang <jeffpang@cs.cmu.edu>. Released under GPL.
 * Modified by Simson Garfinkel
 */

#ifndef _WIFIPCAP_H_
#define _WIFIPCAP_H_

#include <list>
#include <netinet/in.h>

#pragma GCC diagnostic ignored "-Wredundant-decls"
#include <pcap/pcap.h>
#pragma GCC diagnostic warning "-Wredundant-decls"


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

class WifipcapCallbacks {
public:;
/** 48-bit MACs in 64-bits is strangely needed for ieee include files.
 * Oh well.
 */
    struct MAC {          
        uint64_t val;
        MAC():val() {}
        MAC(const uint8_t *stream);
        MAC(uint64_t val);
        MAC(const char *str);
        MAC(const MAC& o);
    
        bool operator==(const MAC& o) const { return val == o.val; }
        bool operator!=(const MAC& o) const { return val != o.val; }
        bool operator<(const MAC& o) const { return val < o.val; }
    
        enum { PRINT_FMT_COLON, PRINT_FMT_PLAIN };
    
        static MAC broadcast;
        static MAC null;
        static int print_fmt;
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
        MAC sa, da;
        uint16_t type;
    };
#ifdef _WIN32
#pragma pack(pop)
#endif


 public:
    WifipcapCallbacks(){};
    virtual ~WifipcapCallbacks(){};

    /**
     * @param t the time the packet was captured
     * @param pkt the entire packet captured
     * @param len the length of the data captured
     * @param origlen the original length of the data (before truncated by pcap)
     */
    virtual void PacketBegin(const struct timeval& t, const u_char *pkt, int len, int origlen) {}
    virtual void PacketEnd() {}

    // If a Prism or RadioTap packet is found, call these, and then call Handle80211()

    virtual void HandlePrism(const struct timeval& t, struct prism2_pkthdr *hdr, const u_char *rest, int len) {}
    virtual void HandleRadiotap(const struct timeval& t, struct radiotap_hdr *hdr, const u_char *rest, int len) {}

    // 802.11 MAC (see ieee802_11.h)

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
    virtual void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da,
                             const MAC& ra, const MAC& ta, const u_char *ptr, int len, bool fcs_ok) {}

    // if this returns true, we'll check the fcs on every frame.
    // Note: if frames are truncated, the fcs check will fail, so you need
    // a complete packet capture for this to be meaningful
    virtual bool Check80211FCS() { return false; }

    // Management
    virtual void Handle80211MgmtBeacon(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtAssocRequest(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtAssocResponse(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtReassocRequest(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtReassocResponse(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtProbeRequest(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtProbeResponse(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtATIM(const struct timeval& t, const struct mgmt_header_t *hdr) {}
    virtual void Handle80211MgmtDisassoc(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtAuth(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}
    virtual void Handle80211MgmtAuthSharedKey(const struct timeval& t, const struct mgmt_header_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211MgmtDeauth(const struct timeval& t, const struct mgmt_header_t *hdr, const struct mgmt_body_t *body) {}

    // Control
    virtual void Handle80211CtrlPSPoll(const struct timeval& t, const struct ctrl_ps_poll_t *hdr) {}
    virtual void Handle80211CtrlRTS(const struct timeval& t, const struct ctrl_rts_t *hdr) {}
    virtual void Handle80211CtrlCTS(const struct timeval& t, const struct ctrl_cts_t *hdr) {}
    virtual void Handle80211CtrlAck(const struct timeval& t, const struct ctrl_ack_t *hdr) {}
    virtual void Handle80211CtrlCFEnd(const struct timeval& t, const struct ctrl_end_t *hdr) {}
    virtual void Handle80211CtrlEndAck(const struct timeval& t, const struct ctrl_end_ack_t *hdr) {}
    
    // Data
    virtual void Handle80211DataIBSS(const struct timeval& t, const struct data_hdr_ibss_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211DataFromAP(const struct timeval& t, const struct data_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211DataToAP(const struct timeval& t, const struct data_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211DataWDS(const struct timeval& t, const struct data_hdr_wds_t *hdr, const u_char *rest, int len) {}
    
    // Erroneous Frames/Truncated Frames
    virtual void Handle80211Unknown(const struct timeval& t, int fc, const u_char *rest, int len) {}

    // LLC/SNAP (see llc.h)

    virtual void HandleLLC(const struct timeval& t, const struct llc_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void HandleLLCUnknown(const struct timeval& t, const u_char *rest, int len) {}
    virtual void HandleWEP(const struct timeval& t, const struct wep_hdr_t *hdr, const u_char *rest, int len) {}
};

extern std::ostream& operator<<(std::ostream& out, const WifipcapCallbacks::MAC& mac);
extern std::ostream& operator<<(std::ostream& out, const struct in_addr& ip);

#include "uni/ieee802_11.h"
#include "uni/ieee802_11_radio.h"
#include "uni/llc.h"


///////////////////////////////////////////////////////////////////////////////

/**
 * Applications create an instance of this to start processing a pcap
 * trace. Example:
 *
 *    Wifipcap *wp = new Wifipcap("/path/to/mytrace.cap");
 *    wp->Run(new MyCallbacks());
 */
class Wifipcap {
    class not_impl: public std::exception {
        virtual const char *what() const throw() {
            return "copying Wifipcap objects is not implemented.";
        }
    };
    Wifipcap(const Wifipcap &t) __attribute__((__noreturn__)):descr(),datalink(),morefiles(),verbose(),
        startTime(),lastPrintTime(),packetsProcessed() {
        throw new not_impl();
    }
    Wifipcap &operator=(const Wifipcap &that){
        throw new not_impl();
    }

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
    };

    struct PcapUserData {
        Wifipcap *wcap;
        WifipcapCallbacks *cbs;
    };

    /** Packet handling callback
     *  @param user - pointer to a PcapUserData struct
     */
    static void dl_prism(u_char *user, const struct pcap_pkthdr *header, const u_char * packet);
    static void dl_ieee802_11_radio(u_char *user, const struct pcap_pkthdr *header, const u_char * packet);

    /**
     * Initialize the lib. Exits with error message upon failure.
     *
     * @param name the device if live = true, else the file name of
     * the trace. If the file name ends in '.gz', we assume its a
     * gzipped trace and will pipe it through zcat before parsing it.
     * @param live true if reading from a device, otherwise a trace
     */
    Wifipcap():descr(),datalink(),morefiles(),verbose(),startTime(),lastPrintTime(),packetsProcessed(){}; 
    Wifipcap(const char *name, bool live = false, bool verbose = false);
    
    /**
     * Initialize with nfiles. Will run on all of them in order.
     */
    Wifipcap(const char* const *names, int nfiles, bool verbose = false);

    virtual ~Wifipcap(){
        if(descr) pcap_close(descr);
    };

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
    void Run(WifipcapCallbacks *cbs, int maxpkts = 0);

    pcap_t *GetPcap() { return descr; }
    int    GetDataLink() { return datalink; }

 private:
    void Init(const char *name, bool live);
    bool InitNext();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    int datalink;
    std::list<const char *> morefiles;

 public:
    bool           verbose;
    struct timeval startTime;
    struct timeval lastPrintTime;
    uint64_t       packetsProcessed;
    static const int PRINT_TIME_INTERVAL = 6*60*60; // sec
};

///////////////////////////////////////////////////////////////////////////////

#endif
