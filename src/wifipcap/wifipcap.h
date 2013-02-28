
/**
 * Include this header in applications using wifipcap.
 */

#ifndef _WIFIPCAP_H_
#define _WIFIPCAP_H_

#include "util.h"

#include <list>
#include <pcap.h>
#ifndef _WIN32
#include <netinet/in.h>
#endif
#include "extract.h"
#include "prism.h"
#include "radiotap.h"
#include "ieee802_11.h"
#include "ether.h"
#include "llc.h"
#include "oui.h"
#include "ethertype.h"
#include "arp.h"
#include "ip.h"
#include "ip6.h"
#include "ipproto.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

#include "TimeVal.h"

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
 public:
    /**
     * @param t the time the packet was captured
     * @param pkt the entire packet captured
     * @param len the length of the data captured
     * @param origlen the original length of the data (before truncated by pcap)
     */
    virtual void PacketBegin(const struct timeval& t, const u_char *pkt, int len, int origlen) {}
    virtual void PacketEnd() {}

    ///// Prism Header (see prism.h)

    virtual void HandlePrism(const struct timeval& t, prism2_pkthdr *hdr, const u_char *rest, int len) {}

    virtual void HandleRadiotap(const struct timeval& t, radiotap_hdr *hdr, const u_char *rest, int len) {}

    ///// 802.11 MAC (see ieee802_11.h)

    // This method is called for every 802.11 frame just before the
    // specific functions below are called. This allows you to have
    // one entry point to easily do something with all 802.11 packets.
    //
    // The MAC addresses will be MAC::null unless applicable to the
    // particular type of packet. For unknown 802.11 packets, all
    // MAC addresses will be MAC::null and if the packet is truncated,
    // so that fc was not decoded, it will be 0.
    //
    // fcs_ok will be true if the frame had a valid fcs trailer and
    // Check80211FCS() returns true.
    virtual void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta, const u_char *ptr, int len, bool fcs_ok) {}

    // if this returns true, we'll check the fcs on every frame.
    // Note: if frames are truncated, the fcs check will fail, so you need
    // a complete packet capture for this to be meaningful
    virtual bool Check80211FCS() { return false; }

    // Management
    virtual void Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtAssocRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtAssocResponse(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtReassocRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtReassocResponse(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtProbeRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtProbeResponse(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtATIM(const struct timeval& t, const mgmt_header_t *hdr) {}
    virtual void Handle80211MgmtDisassoc(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtAuth(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}
    virtual void Handle80211MgmtAuthSharedKey(const struct timeval& t, const mgmt_header_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211MgmtDeauth(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {}

    // Control
    virtual void Handle80211CtrlPSPoll(const struct timeval& t, const ctrl_ps_poll_t *hdr) {}
    virtual void Handle80211CtrlRTS(const struct timeval& t, const ctrl_rts_t *hdr) {}
    virtual void Handle80211CtrlCTS(const struct timeval& t, const ctrl_cts_t *hdr) {}
    virtual void Handle80211CtrlAck(const struct timeval& t, const ctrl_ack_t *hdr) {}
    virtual void Handle80211CtrlCFEnd(const struct timeval& t, const ctrl_end_t *hdr) {}
    virtual void Handle80211CtrlEndAck(const struct timeval& t, const ctrl_end_ack_t *hdr) {}
    
    // Data
    virtual void Handle80211DataIBSS(const struct timeval& t, const data_hdr_ibss_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211DataFromAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211DataToAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void Handle80211DataWDS(const struct timeval& t, const data_hdr_wds_t *hdr, const u_char *rest, int len) {}
    
    // Erroneous Frames/Truncated Frames
    virtual void Handle80211Unknown(const struct timeval& t, int fc, const u_char *rest, int len) {}

    ///// LLC/SNAP (see llc.h)

    virtual void HandleLLC(const struct timeval& t, const llc_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void HandleLLCUnknown(const struct timeval& t, const u_char *rest, int len) {}
    virtual void HandleWEP(const struct timeval& t, const wep_hdr_t *hdr, const u_char *rest, int len) {}
    // for non-802.11 ethernet traces
    virtual void HandleEthernet(const struct timeval& t, const ether_hdr_t *hdr, const u_char *rest, int len) {}

    ///// Layer 2 (see arp.h, ip.h, ip6.h)

    virtual void HandleARP(const struct timeval& t, const arp_pkthdr *hdr, const u_char *rest, int len) {}
    virtual void HandleIP(const struct timeval& t, const ip4_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, int len) {}
    virtual void HandleIP6(const struct timeval& t, const ip6_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void HandleL2Unknown(const struct timeval& t, uint16_t ether_type, const u_char *rest, int len) {}

    ///// Layer 3 (see icmp.h, tcp.h, udp.h)

    // IP headers are included for convenience. one of ip4h, ip6h will
    // be non-NULL. Only the first fragment in a fragmented packet
    // will be decoded. The other fragments will not be passed to any
    // of these functions.

    // Jeff: XXX icmp callback will probably eventually change to
    // parse the entire icmp packet
    virtual void HandleICMP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, int type, int code, const u_char *rest, int len) {}
    virtual void HandleTCP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const tcp_hdr_t *hdr, const u_char *options, int optlen, const u_char *rest, int len) {}
    virtual void HandleUDP(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const udp_hdr_t *hdr, const u_char *rest, int len) {}
    virtual void HandleL3Unknown(const struct timeval& t, const ip4_hdr_t *ip4h, const ip6_hdr_t *ip6h, const u_char *rest, int len) {}
};

///////////////////////////////////////////////////////////////////////////////

/**
 * Applications create an instance of this to start processing a pcap
 * trace. Example:
 *
 *    Wifipcap *wp = new Wifipcap("/path/to/mytrace.cap");
 *    wp->Run(new MyCallbacks());
 */
class Wifipcap {
 public:
    /**
     * Initialize the lib. Exits with error message upon failure.
     *
     * @param name the device if live = true, else the file name of
     * the trace. If the file name ends in '.gz', we assume its a
     * gzipped trace and will pipe it through zcat before parsing it.
     * @param live true if reading from a device, otherwise a trace
     */
    Wifipcap(const char *name, bool live = false, bool verbose = false);
    
    /**
     * Initialize with nfiles. Will run on all of them in order.
     */
    Wifipcap(const char* const *names, int nfiles, bool verbose = false);

    virtual ~Wifipcap();

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
    int GetDataLink() { return datalink; }

 private:
    void Init(const char *name, bool live);
    bool InitNext();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    int datalink;
    std::list<const char *> morefiles;

 public:
    bool verbose;
    struct timeval startTime;
    struct timeval lastPrintTime;
    uint32 packetsProcessed;

    static const int PRINT_TIME_INTERVAL = 6*60*60; // sec
};

///////////////////////////////////////////////////////////////////////////////

/**
 * Utility functions for 802.11 fields.
 */
class WifiUtil {
 public:
    // some functions to convert codes to ascii names
    static const char *MgmtAuthAlg2Txt(int v);
    static const char *MgmtStatusCode2Txt(int v);
    static const char *MgmtReasonCode2Txt(int v);
    static const char *EtherType2Txt(int t);
};

#endif
