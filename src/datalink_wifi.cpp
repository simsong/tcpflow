/**
 * wifi datalink function and callbacks to handle 802.11
 * In addition to calling process_packet_info() for the packets,
 * it maintains some 802.11 specific databases.
 */ 

#include "tcpflow.h"
#include "datalink_wifi.h"

/**
 * TFCB --- TCPFLOW callbacks for wifippcap
 */

void TFCB::Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta,
                     const u_char *ptr, u_int len, bool flag) {
#ifdef DEBUG_WIFI
        cout << "  Handle80211( fcs=" << (int)flag << " len=" << len << ") ";
#endif
	this->fcs_ok = flag;            // the frame checksum
    }

void TFCB::HandleLLC(const struct timeval& t, const struct llc_hdr_t *hdr, const u_char *rest, u_int len) {
        struct timeval tv;
        if (opt_enforce_80211_frame_checksum && !fcs_ok) return;
#ifdef DEBUG_WIFI
        cout << "  HandleLLC(len=" << len << ") ";
#endif
        sbuf_t sb(pos0_t(),rest,len,len,0);

        be13::packet_info pi(DLT_IEEE802_11,(const pcap_pkthdr *)0,(const u_char *)0,tvshift(tv,t),rest,len);
        be13::plugin::process_packet(pi);
    }

void TFCB::Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body)
{
    if (opt_enforce_80211_frame_checksum && fcs_ok==0) return;
#ifdef DEBUG_WIFI
    std::cerr << "  " << "802.11 mgmt: " << hdr->sa << " beacon " << body->ssid.ssid << "\"";
#endif
    mac_ssid bcn(hdr->sa,std::string(body->ssid.ssid,body->ssid.length));
    mac_to_ssid[bcn] += 1;
    for(mac_ssid_map_t::const_iterator it=mac_to_ssid.begin();it!=mac_to_ssid.end();it++){
        std::cerr << (*it).first.mac << " => " << (*it).first.ssid << " (" << (*it).second << ")\n";
    }
    std::cerr << "\n";
}


/* Entrance point */
static Wifipcap wcap;
TFCB theTFCB;
static int counter=0;
void dl_ieee802_11_radio(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    printf("counter=%d\n",counter++);
    //WifipcapCallbacks::debug = 1;
    Wifipcap::PcapUserData data(&wcap,&theTFCB,DLT_IEEE802_11_RADIO);
    Wifipcap::dl_ieee802_11_radio(data,h,p);
}    

void dl_prism(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    Wifipcap::PcapUserData data(&wcap,&theTFCB,DLT_PRISM_HEADER);
    Wifipcap::dl_prism(data,h,p);
}    

        
