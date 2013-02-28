
#include "os.h"

#ifdef _WIN32
#pragma pack(push, 1)
#endif
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
} _PACKED_;
#ifdef _WIN32
#pragma pack(pop)
#endif
