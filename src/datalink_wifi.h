#ifndef DATALINK_WIFI_H
#define DATALINK_WIFI_H

#include <algorithm>
#include <map>
#include "wifipcap.h"

//#define DEBUG_WIFI

class TFCB : public WifipcapCallbacks {
private:

public:
    bool fcs_ok;                        // framechecksum is okay!
    bool opt_enforce_80211_frame_checksum;

    typedef struct mac_ssid {
        mac_ssid(const WifipcapCallbacks::MAC &mac_,const std::string &ssid_):mac(mac_),ssid(ssid_){}
        const WifipcapCallbacks::MAC mac;
        const std::string ssid;
        bool operator<(const struct mac_ssid &b) const{
            if (mac < b.mac) return true;
            if (b.mac < mac) return false;
            return ssid < b.ssid;
        };
    } mac_ssid_t;

        

    typedef struct {
        bool operator() (const struct mac_ssid &a, const struct mac_ssid &b) const {
            if (a.mac < b.mac) return true;
            if (b.mac < a.mac) return false;
            return a.ssid < b.ssid;
        }
    } mac_ssid_lt;
    typedef std::set<mac_ssid_t,mac_ssid_lt> mac_ssid_set_t;
    typedef std::map<mac_ssid_t,uint64_t> mac_ssid_map_t;
    mac_ssid_map_t mac_to_ssid;        // mapping of macs to SSIDs

    static TFCB   theTFCB;
    TFCB():fcs_ok(),opt_enforce_80211_frame_checksum(true),mac_to_ssid(){}

#ifdef DEBUG_WIFI
    void PacketBegin(const struct timeval& t, const u_char *pkt, u_int len, int origlen) {
	cout << t << " {";
    }
    void PacketEnd() {
	cout << "}" << std::endl;
    }
#endif
 
    bool Check80211FCS() { return true; }               // always check the frame checksums
    void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta,
                     const u_char *ptr, u_int len, bool flag);

    void HandleLLC(const struct timeval& t, const struct llc_hdr_t *hdr, const u_char *rest, u_int len);
    void Handle80211MgmtBeacon(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body);
};

#endif
