
#include "os.h"

/*
// prism header: added (from wlan-ng)
#define WLAN_DEVNAMELEN_MAX 16

typedef struct {
    uint32_t did;
    uint16_t status;
    uint16_t len;
    uint32_t data;
} __attribute__((__packed__)) p80211item_uint32_t;

typedef struct {
    uint32_t msgcode;
    uint32_t msglen;
    uint8_t devname[WLAN_DEVNAMELEN_MAX];
    p80211item_uint32_t hosttime;
    p80211item_uint32_t mactime;
    p80211item_uint32_t channel;
    p80211item_uint32_t rssi;
    p80211item_uint32_t sq;
    p80211item_uint32_t signal;
    p80211item_uint32_t noise;
    p80211item_uint32_t rate;
    p80211item_uint32_t istx;
    p80211item_uint32_t frmlen;
}  __attribute__((__packed__)) prism2_pkthdr;
*/

#ifdef _WIN32
#pragma pack(push, 1)
#endif
struct prism2_pkthdr {
    u_int32_t host_time;
    u_int32_t mac_time;
    u_int32_t channel;
    u_int32_t rssi;
    u_int32_t sq;
    int       signal;
    int       noise;
    u_int32_t rate;
    u_int32_t istx;
    u_int32_t frmlen;
} _PACKED_;
#ifdef _WIN32
#pragma pack(pop)
#endif
