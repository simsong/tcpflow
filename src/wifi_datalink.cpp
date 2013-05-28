/**
 * wifi datalink function and callbacks to handle 802.11
 * In addition to calling process_packet_info() for the packets,
 * it maintains some 802.11 specific databases.
 */ 


#ifndef WIN32

#include "tcpflow.h"
#include "wifipcap.h"
#include <algorithm>
#include <map>


bool opt_enforce_80211_frame_checksum = true; // by default, only give good checksums

/**
 * TFWC --- TCPFLOW callbacks for wifippcap
 */

class TFWC : public WifipcapCallbacks {
private:
    bool fcs_ok;                        // framechecksum is okay!
    typedef pair<const WifipcapCallbacks::MAC *,const char *> mac_ssid_pair;
    typedef struct {
        bool operator() (const mac_ssid_pair &a, const mac_ssid_pair &b) const {
            if (*(a.first) < (*(b.first))) return true;
            if (*(b.first) < (*(a.first))) return false;
            return strcmp(a.second,b.second) < 0;
        }
    } mac_ssid_pair_lt;
    typedef std::set<mac_ssid_pair,mac_ssid_pair_lt> mac_ssids_seen_t;
    mac_ssids_seen_t mac_ssids_seen;

public:
    TFWC():fcs_ok(),mac_ssids_seen(){};

#ifdef DEBUG_WIFI
    void PacketBegin(const struct timeval& t, const u_char *pkt, int len, int origlen) {
	cout << t << " {" << endl;
    }
    void PacketEnd() {
	cout << "}" << endl;
    }
#endif
 
    bool Check80211FCS() { return opt_enforce_80211_frame_checksum; } // check the frame checksums
    void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta,
                     const u_char *ptr, int len, bool flag) {
	this->fcs_ok = flag;
    }

    void HandleLLC(const struct timeval& t, const struct llc_hdr_t *hdr, const u_char *rest, int len) {
        if (opt_enforce_80211_frame_checksum && !fcs_ok) return;
#ifdef DEBUG_WIFI
        cout << "  " << "802.11 LLC :\t" << "len=" << len << endl;
#endif
    }

    void Handle80211DataFromAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) {
        if (opt_enforce_80211_frame_checksum && !fcs_ok) return;
#ifdef DEBUG_WIFI
        cout << hdr->sa;
        cout << "  " << "802.11 data from AP:\t" 
             << hdr->sa << " -> " << hdr->da << "\t" << len << endl;
#endif
        struct timeval tv;
        /* TK1: Does the pcap header make sense? */
        /* TK2: How do we get and preserve the the three MAC addresses? */

        printf("DATA_HDRLEN=%d  DATA_WDS_HDRLEN=%d\n",DATA_HDRLEN,DATA_WDS_HDRLEN);

        sbuf_t sb(pos0_t(),rest,len,len,0);
        sb.hex_dump(std::cout);

        rest += 10;                     // where does 10 come from? 
        len -= 10;

        be13::packet_info pi(DLT_IEEE802_11,(const pcap_pkthdr *)0,(const u_char *)0,tvshift(tv,t),rest,len);
        printf("pi.ip_version=%d\n",pi.ip_version());
        be13::plugin::process_packet_info(pi);
    }
    void Handle80211DataToAP(const struct timeval& t, const data_hdr_t *hdr, const u_char *rest, int len) {
        if (opt_enforce_80211_frame_checksum && !fcs_ok) return;
#ifdef DEBUG_WIFI
        cout << "  " << "802.11 data to AP:\t" 
             << hdr->sa << " -> " << hdr->da << "\t" << len << endl;
#endif
        struct timeval tv;
        /* TK1: Does the pcap header make sense? */
        /* TK2: How do we get and preserve the the three MAC addresses? */
        be13::packet_info pi(DLT_IEEE802_11,(const pcap_pkthdr *)0,(const u_char *)0,tvshift(tv,t),rest,len);
        be13::plugin::process_packet_info(pi);
    }

    /* This implementation only cares about beacons, so that's all we record */
    void Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body) {
        if (opt_enforce_80211_frame_checksum && !fcs_ok) return;
#ifdef DEBUG_WIFI
        cout << "  " << "802.11 mgmt:\t" 
             << hdr->sa << "\tbeacon\t\"" << body->ssid.ssid << "\"" << endl;
#endif
        mac_ssid_pair ptest(&hdr->sa,body->ssid.ssid);

        //cout << "check " << hdr->sa << " to " << body->ssid.ssid << "\n";


        if(mac_ssids_seen.find(ptest)==mac_ssids_seen.end()){
            const MAC *m2 = new MAC(hdr->sa);
            const char *s2 = strdup(body->ssid.ssid);
            mac_ssid_pair pi(m2,s2);
            
            cout << "new mapping " << *ptest.first << "->" << ptest.second << "\n";
            mac_ssids_seen.insert(pi);
            /* TK3: How do we get this into the XML? */
        }
    }
};

/* Entrance point */
static Wifipcap *wcap = 0;
static Wifipcap::PcapUserData data;
void dl_ieee802_11_radio(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    if(wcap==0){
        wcap = new Wifipcap();
        data.wcap = wcap;
        data.cbs  = new TFWC();
    }
    Wifipcap::dl_ieee802_11_radio(reinterpret_cast<u_char *>(&data),h,p);
}    

void dl_prism(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    if(wcap==0){
        wcap = new Wifipcap();
        data.wcap = wcap;
        data.cbs  = new TFWC();
    }
    Wifipcap::dl_prism(reinterpret_cast<u_char *>(&data),h,p);
}    

        
#endif
