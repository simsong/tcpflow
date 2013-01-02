/**
 * pcap visualization engine 
 */

#include "config.h"
#include <iostream>
#include <sys/types.h>
#include "bulk_extractor_i.h"
#include "netviz/one_page_report.h"
#include "netviz/time_histogram.h"

one_page_report th_one_page(one_page_report::default_config);

void th_startup()
{
    th_one_page = one_page_report(one_page_report::default_config);
}

void th_process_packet(void *user,const packet_info &pi)
{
    th_one_page.ingest_packet(pi);
}

void th_shutdown(const class scanner_params &sp)
{
    th_one_page.source_identifier = sp.fs.input_fname;
    th_one_page.render(sp.fs.outdir);
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
