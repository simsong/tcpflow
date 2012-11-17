/**
 * pcap visualization engine 
 */

#include "config.h"
#include <iostream>
#include <sys/types.h>
#include "bulk_extractor_i.h"
#include "time_histogram.h"

// previously the namespace time_plugin 


/* This should become a class that runs all of the time histograms and then selects the correct one for plotting */

const int num_histograms = 6;

// this vector must hold histograms in order from greatest time resolution
// to least
static vector<time_histogram> histograms;

/* select_for_render renders the actual one we want */

time_histogram *select_for_render()
{
    // assume the lowest resolution histogram is best
    time_histogram *best = &histograms.back();
    
    // use the highest resolution histogram with no overflowed packets, or
    // use the lowest resolution histogram if all have overflow, since it
    // should almost certainly have the least since it's span is the largest
    // Histograms must be in descending order of resolution
    for(vector<time_histogram>::iterator candidate = histograms.begin();
	candidate != histograms.end(); candidate++) {
	uint64_t dropped = candidate->underflow_count +
	    candidate->overflow_count;
	
	if(dropped == 0) {
	    // this seems bad, but I don't think there's a better way.
	    best = &(*candidate);
	    break;
	}
    }
    
    return best;
}

void th_startup()
{
    time_histogram::histogram_config_t config = time_histogram::default_histogram_config;
    config.graph.title = "TCP Packets Received";
    config.graph.filename = "time_histogram.pdf";
    
    // create and insert histograms in descending time resolution order
    for(int ii = 0; ii < num_histograms; ii++) {
	histograms.push_back(time_histogram((span_t)ii, config));
    }
}

void histogram_process_packet(void *user,const packet_info &pi)
{
    for(vector<time_histogram>::iterator histogram = histograms.begin();
	histogram != histograms.end(); histogram++) {
	(*histogram).ingest_packet(pi);
    }
}

void th_shutdown(const class scanner_params &sp)
{
    time_histogram *to_render = select_for_render();
    to_render->render(sp.fs.outdir);
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
	sp.info->packet_cb = histogram_process_packet;

	th_startup();
    }

    if(sp.phase==scanner_params::scan){	// this is for scanning sbufs
	return;
    }

    if(sp.phase==scanner_params::shutdown){
	th_shutdown(sp);
    }

}
