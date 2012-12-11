/**
 * pcap visualization engine 
 */

#include "config.h"
#include <iostream>
#include <sys/types.h>
#include "bulk_extractor_i.h"
#include "netviz/time_histogram.h"

dyn_time_histogram th_histogram(time_histogram::default_config);

void th_startup()
{
    time_histogram::config_t config = time_histogram::default_config;
    config.graph.title = "TCP Packets Received";
    config.graph.filename = "time_histogram.pdf";

    th_histogram = dyn_time_histogram(config);
}

void th_process_packet(void *user,const packet_info &pi)
{
    th_histogram.ingest_packet(pi);
}

void th_shutdown(const class scanner_params &sp)
{
    th_histogram.render(sp.fs.outdir);
}


extern "C"
void  scan_netviz(const class scanner_params &sp,const recursion_control_block &rcb)
{

    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_timehistogram requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::startup){
	sp.info->name  = "netviz";
	sp.info->flags = scanner_info::SCANNER_DISABLED;
	sp.info->author= "Mike Shick";
	sp.info->packet_user = 0;
	sp.info->packet_cb = th_process_packet;

	th_startup();
    }

    if(sp.phase==scanner_params::scan){	// this is for scanning sbufs
	return;
    }

    if(sp.phase==scanner_params::shutdown){
	th_shutdown(sp);
    }

}
