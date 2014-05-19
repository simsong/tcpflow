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

/* These control the size of the iptable histogram
 * and whether or not it is dumped. The histogram should be kept
 * either small enough that it is not expensive to maintain, or large
 * enough so that it never needs to be pruned.
 */

#define HISTOGRAM_SIZE "netviz_histogram_size"
#define HISTOGRAM_DUMP "netviz_histogram_dump"
#define DEFAULT_MAX_HISTOGRAM_SIZE 1000 

static one_page_report *report=0;
static void netviz_process_packet(void *user,const be13::packet_info &pi)
{
    report->ingest_packet(pi);
}

#endif

#ifdef HAVE_LIBCAIRO
static int histogram_dump = 0;
#endif

extern "C"
void  scan_netviz(const class scanner_params &sp,const recursion_control_block &rcb)
{
    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cout << "scan_timehistogram requires sp version "
		  << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
	sp.info->name  = "netviz";
	sp.info->flags = scanner_info::SCANNER_DISABLED; // disabled by default
	sp.info->author= "Mike Shick";
	sp.info->packet_user = 0;
#ifdef HAVE_LIBCAIRO
        sp.info->description = "Performs 1-page visualization of network packets";
	sp.info->packet_cb = netviz_process_packet;
        sp.info->get_config(HISTOGRAM_DUMP,&histogram_dump,"Dumps the histogram");
        int max_histogram_size = DEFAULT_MAX_HISTOGRAM_SIZE;
        sp.info->get_config(HISTOGRAM_SIZE,&max_histogram_size,"Maximum histogram size");
        report = new one_page_report(max_histogram_size);
#else
        sp.info->description = "Disabled (compiled without libcairo";
#endif
    }
#ifdef HAVE_LIBCAIRO

    if(sp.phase==scanner_params::PHASE_SHUTDOWN){
        assert(report!=0);
        if(histogram_dump){
            report->src_tree.dump_stats(std::cout);
            report->dump(histogram_dump);
        }
        report->source_identifier = sp.fs.get_input_fname();
        report->render(sp.fs.get_outdir());
        delete report;
        report = 0;
    }
#endif
}

