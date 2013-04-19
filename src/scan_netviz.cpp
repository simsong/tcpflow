/**
 * scan_netviz:
 * 
 * Our first try at a pcap visualization engine.
 * Requires LIBCAIRO
 */

#include "config.h"
#include <iostream>
#include <sys/types.h>

#include "bulk_extractor_i.h"

#ifdef HAVE_LIBCAIRO
#include "netviz/one_page_report.h"
static one_page_report *report=0;

static void netviz_startup()
{
    assert(report==0);
    report = new one_page_report();
}

static void netviz_process_packet(void *user,const be13::packet_info &pi)
{
    report->ingest_packet(pi);
}

static void netviz_shutdown(const class scanner_params &sp)
{
    assert(report!=0);
    report->source_identifier = sp.fs.input_fname;
    report->render(sp.fs.outdir);
    delete report;
    report = 0;
}
#endif


extern "C"
void  scan_netviz(const class scanner_params &sp,const recursion_control_block &rcb)
{
    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_timehistogram requires sp version "
		  << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
#ifdef HAVE_LIBCAIRO
	sp.info->name  = "netviz";
	//sp.info->flags = scanner_info::SCANNER_DISABLED;
        sp.info->flags = 0;
	sp.info->author= "Mike Shick";
	sp.info->packet_user = 0;
	sp.info->packet_cb = netviz_process_packet;
	netviz_startup();
#endif	
    }

    if(sp.phase==scanner_params::PHASE_SHUTDOWN){
#ifdef HAVE_LIBCAIRO
        report->src_tree.dump_stats(std::cerr);
	netviz_shutdown(sp);
#endif
    }
}
