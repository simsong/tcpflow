/**
 * scan_wifiviz:
 * 
 * Use the wifipcap and do some basic visualizations
 */

#include "config.h"
#include <iostream>
#include <sys/types.h>

#include "bulk_extractor_i.h"
#include "datalink_wifi.h"

extern "C"
void  scan_wifiviz(const class scanner_params &sp,const recursion_control_block &rcb)
{
    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cout << "scan_timehistogram requires sp version "
		  << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
	sp.info->name  = "wifiviz";
	sp.info->flags = scanner_info::SCANNER_DISABLED;
	sp.info->author= "Simson Garfinkel";
	sp.info->packet_user = 0;
        sp.info->description = "Performs wifi isualization";
    }
    if(sp.phase==scanner_params::PHASE_SHUTDOWN){
        extern TFCB theTFCB;
        for(TFCB::mac_ssid_map_t::const_iterator it=theTFCB.mac_to_ssid.begin();
            it!=theTFCB.mac_to_ssid.end();it++){
            std::cerr << (*it).first.mac << " => "
                      << (*it).first.ssid << " (" << (*it).second << ")\n";
        }
        std::cerr << "\n";
        
    }
}

