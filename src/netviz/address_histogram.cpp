/**
 * address_histogram.cpp: 
 * Show packets received vs address
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"

#include "address_histogram.h"

const address_histogram::config_t address_histogram::default_config = {
    /* graph */ plot::default_config,
    /* relationship */ address_histogram::SND_OR_RCV,
    /* bar_space_factor */ 1.2,
    /* max_bars */ 10
};

//void address_histogram::ingest_packet(const packet_info &pi)
//{
    //uint64_t time = pi.ts.tv_usec + pi.ts.tv_sec * 1000000L; // microseconds
    //// if we haven't received any data yet, we need to set the base time
    //if(!received_data) {
	//uint64_t first_bucket = (uint64_t) ((double) conf.bucket_count *
                //conf.first_bucket_factor);
	//base_time = time - (bucket_width * first_bucket);
	//received_data = true;
    //}
//
    //int target_index = (time - base_time) / bucket_width;
//
    //if(target_index < 0) {
	//underflow_count++;
	//return;
    //}
    //if(target_index >= conf.bucket_count) {
	//overflow_count++;
	//return;
    //}
//
    //bucket_t *target_bucket = &buckets.at(target_index);
//
    //switch(net_tcp::get_port(pi)) {
    //case PORT_HTTP:
    //case PORT_HTTP_ALT_0:
    //case PORT_HTTP_ALT_1:
    //case PORT_HTTP_ALT_2:
    //case PORT_HTTP_ALT_3:
    //case PORT_HTTP_ALT_4:
    //case PORT_HTTP_ALT_5:
	//target_bucket->http++;
	//break;
    //case PORT_HTTPS:
	//target_bucket->https++;
	//break;
    //case -1:
	//// get_tcp_port() returns -1 for any error, including if
	//// there isn't a TCP segment in the packet
	//break;
    //default:
	//target_bucket->other++;
    //}
//}
//
//void address_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
//{
//#ifdef CAIRO_PDF_AVAILABLE
    //render_vars vars;
    //vars.prep(*this);
//
    //// if there aren't any significant buckets, abort.
    //if(vars.num_sig_buckets < 1) {
	//return;
    //}
//
    //choose_subtitle(vars);
//
    //plot::ticks_t ticks = build_tick_labels(vars);
    //plot::legend_t legend = build_legend(vars);
    //plot::bounds_t content_bounds(0.0, 0.0, bounds.width,
            //bounds.height);
//
    //// have the plot class do labeling, axes, legend etc
    //plot::render(cr, bounds, ticks, legend, conf.graph, content_bounds);
//
    //// fill borders rendered by plot class
    //render_bars(cr, content_bounds, vars);
//#endif
//}
