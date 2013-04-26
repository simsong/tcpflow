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

#define HISTOGRAM_SIZE "netviz_histogram_size"
#define HISTOGRAM_DUMP "netviz_histogram_dump"
#define DEFAULT_MAX_HISTOGRAM_SIZE 1000000

static one_page_report *report=0;
static void netviz_process_packet(void *user,const be13::packet_info &pi)
{
    report->ingest_packet(pi);
}

#endif

static int histogram_dump = 0;

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
#ifdef HAVE_LIBCAIRO
	sp.info->name  = "netviz";
	//sp.info->flags = scanner_info::SCANNER_DISABLED;
        sp.info->flags = 0;
	sp.info->author= "Mike Shick";
	sp.info->packet_user = 0;
	sp.info->packet_cb = netviz_process_packet;
        histogram_dump = atoi(sp.info->config[HISTOGRAM_DUMP].c_str());
        int max_histogram_size = atoi(sp.info->config[HISTOGRAM_SIZE].c_str());
        if(max_histogram_size<=0) max_histogram_size = DEFAULT_MAX_HISTOGRAM_SIZE;
        std::cout << "max_histogram_size=" << max_histogram_size <<"\n";
        report = new one_page_report(max_histogram_size);
#endif	
    }

    if(sp.phase==scanner_params::PHASE_SHUTDOWN){
#ifdef HAVE_LIBCAIRO
        report->src_tree.dump_stats(std::cout);
        assert(report!=0);
        report->dump(histogram_dump);
        report->source_identifier = sp.fs.input_fname;
        report->render(sp.fs.outdir);
        delete report;
        report = 0;
#endif
    }
}
