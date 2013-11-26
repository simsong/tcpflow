#ifndef DATALINK_WIFI_H
#define DATALINK_WIFI_H

#include <algorithm>
#include <map>
#include "wifipcap.h"

//#define DEBUG_WIFI

class TFCB : public WifipcapCallbacks {
private:

public:
    bool opt_check_fcs;

    typedef struct mac_ssid {
        mac_ssid(const MAC &mac_,const std::string &ssid_):mac(mac_),ssid(ssid_){}
        const MAC mac;
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
    TFCB():opt_check_fcs(true),mac_to_ssid(){}

    virtual bool Check80211FCS(const WifiPacket &p) { return opt_check_fcs; }  
    virtual void Handle80211(const WifiPacket &p,u_int16_t fc, const MAC& sa, const MAC& da,
                             const MAC& ra, const MAC& ta, const u_char *ptr, size_t len)  ;

    void HandleLLC(const WifiPacket &p,const struct llc_hdr_t *hdr, const u_char *rest, size_t len) ;
    void Handle80211MgmtBeacon(const WifiPacket &p,const mgmt_header_t *hdr, const mgmt_body_t *body) ;
};

#endif
