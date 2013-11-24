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
        sp.info->get_config("check_fcs",&TFCB::theTFCB.opt_check_fcs,"Require valid Frame Check Sum (FCS)");
    }
    if(sp.phase==scanner_params::PHASE_SHUTDOWN){
        if(sp.sxml){
            (*sp.sxml) << "<ssids>\n";
            for(TFCB::mac_ssid_map_t::const_iterator it=TFCB::theTFCB.mac_to_ssid.begin();
                it!=TFCB::theTFCB.mac_to_ssid.end();it++){
                (*sp.sxml) << "  <ssid mac='" << (*it).first.mac <<"' ssid='" << dfxml_writer::xmlescape((*it).first.ssid) << "' count='" <<
                    (*it).second << "'/>\n";
            }
            (*sp.sxml) << "</ssids>\n";
        }
    }
}

