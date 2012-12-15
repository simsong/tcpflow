/**
 * time_histogram.cpp: 
 * Make fancy time histograms
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"
#include "net_ip.h"
#include "net_tcp.h"

#include <math.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <vector>

#include "time_histogram.h"

using namespace std;

const time_histogram::config_t time_histogram::default_config = {
    /* graph */ plot::default_config,
    /* span */ time_histogram::MINUTE,
    /* bar_space_factor */ 1.2,
    /* bucket_count */ 600,
    /* first_bucket_factor */ 0.1
};

// Unit in libpcap is microsecond, so shall it be here
const uint64_t time_histogram::span_lengths[] = {
    /* minute */ 60L * 1000L * 1000L,
    /* hour */ 60L * 60L * 1000L * 1000L,
    /* day */ 24L * 60L * 60L * 1000L * 1000L,
    /* week */ 7L * 24L * 60L * 60L * 1000L * 1000L,
    /* month */ 30L * 24L * 60L * 60L * 1000L * 1000L,
    /* year */ 12L * 30L * 24L * 60L * 60L * 1000L * 1000L
};

const char * const time_histogram::unit_strings[] = {
    "packets vs time",
    "kilopackets vs time",
    "megapackets vs time",
    "gigapackets vs time",
    "terapackets vs time",
    "petapackets vs time",
    "exapackets vs time",
};

//
// Helper functions
//

void time_histogram::time_struct_to_string(const struct tm &time_struct,
        stringstream &ss)
{
    ss << setfill('0');
    ss << setw(4) << (1900 + time_struct.tm_year) << "-";
    ss << setw(2) << (1 + time_struct.tm_mon) << "-";
    ss << setw(2) << time_struct.tm_mday << " ";
    ss << setw(2) << time_struct.tm_hour << ":";
    ss << setw(2) << time_struct.tm_min << ":";
    ss << setw(2) << time_struct.tm_sec;
}
#pragma GCC diagnostic warning "-Wcast-align"

//
// Rendering classes
//

void time_histogram::ingest_packet(const packet_info &pi)
{
    uint64_t time = pi.ts.tv_usec + pi.ts.tv_sec * 1000000L; // microseconds
    // if we haven't received any data yet, we need to set the base time
    if(!received_data) {
	uint64_t first_bucket = (uint64_t) ((double) conf.bucket_count *
                conf.first_bucket_factor);
	base_time = time - (bucket_width * first_bucket);
	received_data = true;
    }

    int target_index = (time - base_time) / bucket_width;

    if(target_index < 0) {
	underflow_count++;
	return;
    }
    if(target_index >= conf.bucket_count) {
	overflow_count++;
	return;
    }

    bucket_t *target_bucket = &buckets.at(target_index);

    switch(net_tcp::get_port(pi)) {
    case PORT_HTTP:
    case PORT_HTTP_ALT_0:
    case PORT_HTTP_ALT_1:
    case PORT_HTTP_ALT_2:
    case PORT_HTTP_ALT_3:
    case PORT_HTTP_ALT_4:
    case PORT_HTTP_ALT_5:
	target_bucket->http++;
	break;
    case PORT_HTTPS:
	target_bucket->https++;
	break;
    case -1:
	// get_tcp_port() returns -1 for any error, including if
	// there isn't a TCP segment in the packet
	break;
    default:
	target_bucket->other++;
    }
}

void time_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
{
#ifdef CAIRO_PDF_AVAILABLE
    render_vars vars;
    vars.prep(*this);

    // if there aren't any significant buckets, abort.
    if(vars.num_sig_buckets < 1) {
	return;
    }

    choose_subtitle(vars);

    plot::ticks_t ticks = build_tick_labels(vars);
    plot::legend_t legend = build_legend(vars);
    plot::bounds_t content_bounds(0.0, 0.0, bounds.width,
            bounds.height);

    // have the plot class do labeling, axes, legend etc
    plot::render(cr, bounds, ticks, legend, conf.graph, content_bounds);

    // fill borders rendered by plot class
    render_bars(cr, content_bounds, vars);
#endif
}

void time_histogram::render(const std::string &outdir)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_t *cr;
    cairo_surface_t *surface;
    std::string fname = outdir + "/" + conf.graph.filename;

    surface = cairo_pdf_surface_create(fname.c_str(),
				 conf.graph.width,
				 conf.graph.height);
    cr = cairo_create(surface);

    plot::bounds_t bounds(0.0, 0.0, conf.graph.width,
            conf.graph.height);

    render(cr, bounds);

    // cleanup
    cairo_destroy (cr);
    cairo_surface_destroy(surface);
#endif
}

void time_histogram::render_vars::prep(const time_histogram &graph)
{
    // initial stat sweep:
    //   - how many significant buckets are there
    //     (between the first and last nonzero bucket)
    //   - What is the tallest bucket?
    int index = 0;
    for(vector<bucket_t>::const_iterator bucket = graph.buckets.begin();
	bucket != graph.buckets.end(); bucket++) {
	uint64_t bucket_sum = (*bucket).http + (*bucket).https
	    + (*bucket).other;

	// look for first and last significant bucket
	if(bucket_sum > 0) {
	    last_index = index;
	    if(first_index < 0) {
		first_index = index;
	    }
	}

	// look for tallest bucket (most packets)
	if(bucket_sum > greatest_bucket_sum) {
	    greatest_bucket_sum = bucket_sum;
	}

	index++;
    }
    num_sig_buckets = last_index - first_index;

    unit_log_1000 = (uint64_t) (log(greatest_bucket_sum) / log(1000));
}

void time_histogram::choose_subtitle(const render_vars &vars)
{
    // choose subtitle based on magnitude of units
    conf.graph.subtitle = unit_strings[0];
    if(vars.unit_log_1000 < (sizeof(unit_strings) / sizeof(char *))) {
	conf.graph.subtitle = unit_strings[vars.unit_log_1000];
    }
}

plot::ticks_t time_histogram::build_tick_labels(const render_vars &vars)
{
    plot::ticks_t ticks;
    stringstream formatted;

    // y ticks (packet count)

    // scale raw bucket totals

    double y_scale_range = vars.greatest_bucket_sum /
	pow(1000.0, (double) vars.unit_log_1000);
    double y_scale_interval = y_scale_range /
	(conf.graph.y_tick_count - 1);

    for(int ii = 0; ii < conf.graph.y_tick_count; ii++) {
	formatted << setprecision(2) << fixed;
	formatted << ((conf.graph.y_tick_count - (ii + 1)) *
		      y_scale_interval);

	ticks.y_labels.push_back(formatted.str());

	formatted.str(string());
    }

    // x ticks (localtime)

    const time_t start_unix = (base_time +
            (bucket_width * vars.first_index)) / (1000 * 1000);
    const time_t stop_unix = (base_time +
            (bucket_width * vars.last_index)) / (1000 * 1000);
    struct tm start_time = *localtime(&start_unix);
    struct tm stop_time = *localtime(&stop_unix);
        
    time_struct_to_string(start_time, formatted);
    ticks.x_labels.push_back(formatted.str());
    formatted.str(string());
    time_struct_to_string(stop_time, formatted);
    ticks.x_labels.push_back(formatted.str());
    formatted.str(string());

    return ticks;
}

plot::legend_t time_histogram::build_legend(const render_vars &vars)
{
    plot::legend_t legend;

    legend.push_back(plot::legend_entry_t(color_http, "HTTP"));
    legend.push_back(plot::legend_entry_t(color_https, "HTTPS"));
    legend.push_back(plot::legend_entry_t(color_other, "Other"));

    return legend;
}

void time_histogram::render_bars(cairo_t *cr, const plot::bounds_t &bounds,
        render_vars &vars)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_matrix_t original_matrix;

    cairo_get_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    double offset_unit = bounds.width / vars.num_sig_buckets;
    double bar_width = offset_unit / conf.bar_space_factor;
    int index = 0;
    for(vector<bucket_t>::iterator bucket =
	    buckets.begin() + vars.first_index;
	bucket != buckets.begin() + vars.last_index; bucket++) {
	uint64_t bucket_sum = bucket->http + bucket->https + bucket->other;
	double bar_height = (((double) bucket_sum)
                / ((double) vars.greatest_bucket_sum)) * bounds.height;

	if(bar_height > 0) {
	    double http_height = (((double) bucket->http) /
				  ((double) bucket_sum)) * bar_height;
	    double https_height = (((double) bucket->https) /
				   ((double) bucket_sum)) * bar_height;
	    double other_height = (((double) bucket->other) /
				   ((double) bucket_sum)) * bar_height;

	    double current_height = bounds.height - bar_height;

	    // HTTP (blue)
	    cairo_set_source_rgb(cr, color_http.r, color_http.g,
				 color_http.b);
	    cairo_rectangle(cr, index * offset_unit, current_height,
			    bar_width, http_height);
	    cairo_fill(cr);

	    current_height += http_height;

	    // HTTPS (green)
	    cairo_set_source_rgb(cr, color_https.r, color_https.g,
				 color_https.b);
	    cairo_rectangle(cr, index * offset_unit, current_height,
			    bar_width, https_height);
	    cairo_fill(cr);

	    current_height += https_height;

	    // other (yellow)
	    cairo_set_source_rgb(cr, color_other.r, color_other.g,
				 color_other.b);
	    cairo_rectangle(cr, index * offset_unit, current_height,
			    bar_width, other_height);
	    cairo_fill(cr);

	    // reset to black
	    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
	}
	index++;
    }

    cairo_set_matrix(cr, &original_matrix);
#endif
}

//
// Dynamic time histogram
//

dyn_time_histogram::dyn_time_histogram(const time_histogram::config_t &conf_) :
    conf(conf_), histograms()
{
    for(int ii = time_histogram::MINUTE; ii <= time_histogram::YEAR; ii++) {
        time_histogram::config_t config = conf;
        config.span = (time_histogram::span_t) ii;
	histograms.push_back(time_histogram(config));
    }
}

void dyn_time_histogram::ingest_packet(const packet_info &pi)
{
    for(vector<time_histogram>::iterator histogram = histograms.begin();
            histogram != histograms.end(); histogram++) {
        histogram->ingest_packet(pi);
    }
}

void dyn_time_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
{
    select_best_fit().render(cr, bounds);
}

void dyn_time_histogram::render(const std::string &outdir)
{
    select_best_fit().render(outdir);
}

time_histogram &dyn_time_histogram::select_best_fit()
{
    // assume the lowest resolution histogram is best
    time_histogram *best = &histograms.back();
    
    // use the highest resolution histogram with no overflowed packets, or
    // use the lowest resolution histogram if all have overflow, since it
    // should almost certainly have the least since its span is the largest
    // Histograms must be in descending order of resolution
    for(vector<time_histogram>::iterator candidate = histograms.begin();
	candidate != histograms.end(); candidate++) {
	uint64_t dropped = candidate->underflow_count +
	    candidate->overflow_count;
	
	if(dropped == 0) {
	    best = &(*candidate);
	    break;
	}
    }
    
    return *best;
}
