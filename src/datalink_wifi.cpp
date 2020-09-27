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

void TFCB::Handle80211(const WifiPacket &p, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta, const u_char *ptr, size_t len)
{
}

void TFCB::HandleLLC(const WifiPacket &p, const struct llc_hdr_t *hdr, const u_char *rest, size_t len) {
    sbuf_t sb(pos0_t(),rest,len,len,0,false,false,false);
    struct timeval tv;
    be13::packet_info pi(p.header_type,p.header,p.packet,tvshift(tv,p.header->ts),rest,len);
    be13::plugin::process_packet(pi);
}

void TFCB::Handle80211MgmtBeacon(const WifiPacket &p, const mgmt_header_t *hdr, const mgmt_body_t *body)
{
#ifdef DEBUG_WIFI
    std::cerr << "  " << "802.11 mgmt: " << hdr->sa << " beacon " << body->ssid.ssid << "\"";
#endif
    mac_ssid bcn(hdr->sa,std::string(body->ssid.ssid));
    mac_to_ssid[bcn] += 1;
}


/* Entrance point */
TFCB TFCB::theTFCB;                           // singleton
static Wifipcap theWcap;
void dl_ieee802_11_radio(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    theWcap.handle_packet(&TFCB::theTFCB,DLT_IEEE802_11_RADIO,h,p);
}

void dl_prism(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
#ifdef DLT_PRISM_HEADER
    theWcap.handle_packet(&TFCB::theTFCB,DLT_PRISM_HEADER,h,p);
#endif
}
