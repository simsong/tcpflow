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
#include "tcpip.h"

#include <math.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <vector>

#include "time_histogram.h"

using namespace std;

// Unit in libpcap is microsecond, so shall it be here
const uint64_t time_histogram::span_lengths[] = {
    /* minute */ 60L * 1000L * 1000L,
    /* hour */ 60L * 60L * 1000L * 1000L,
    /* day */ 24L * 60L * 60L * 1000L * 1000L,
    /* week */ 7L * 24L * 60L * 60L * 1000L * 1000L,
    /* month */ 30L * 24L * 60L * 60L * 1000L * 1000L,
    /* year */ 12L * 30L * 24L * 60L * 60L * 1000L * 1000L
};

const std::vector<time_histogram::si_prefix> time_histogram::si_prefixes =
        time_histogram::build_si_prefixes();
const std::vector<time_histogram::time_unit> time_histogram::time_units =
        time_histogram::build_time_units();

/**
 * callback which handles each packet.
 */

void time_histogram::ingest_packet(const packet_info &pi, const struct tcp_seg *optional_tcp)
{
    uint64_t time = pi.ts.tv_usec + pi.ts.tv_sec * 1000000L; // microseconds
    // if we haven't received any data yet, we need to set the base time
    if(!received_data) {
	uint64_t first_bucket = (uint64_t) ((double) bucket_count *
                first_bucket_factor);
	base_time = time - (bucket_width * first_bucket);
	received_data = true;
    }

    int target_index = (time - base_time) / bucket_width;

    if(target_index < 0) {
	underflow_count++;
	return;
    }
    if(target_index >= bucket_count) {
	overflow_count++;
	return;
    }

    bucket_t *target_bucket = &buckets.at(target_index);

    // bail if no TCP segment was given (should there be another bucket value for this?)
    if(!optional_tcp) {
        return;
    }

    uint16_t port = ntohs(optional_tcp->header->th_sport);

    switch(port) {
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

    build_axis_labels(vars);

    plot::ticks_t ticks = build_tick_labels(vars);
    plot::legend_t legend;
    plot::bounds_t content_bounds(0.0, 0.0, bounds.width,
            bounds.height);

    // have the plot class do labeling, axes, legend etc
    parent.render(cr, bounds, ticks, legend, content_bounds);

    // fill borders rendered by plot class
    render_bars(cr, content_bounds, vars);
#endif
}

void time_histogram::render(const std::string &outdir)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_t *cr;
    cairo_surface_t *surface;
    std::string fname = outdir + "/" + parent.filename;

    surface = cairo_pdf_surface_create(fname.c_str(),
				 parent.width,
				 parent.height);
    cr = cairo_create(surface);

    plot::bounds_t bounds(0.0, 0.0, parent.width,
            parent.height);

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

void time_histogram::build_axis_labels(const render_vars &vars)
{
    parent.subtitle = "";
    // choose y axis label
    parent.y_label = "packets";
    // choose x axis label
    uint64_t bar_interval = bucket_width / (1000 * 1000);
    if(bar_interval < 1) {
        parent.x_label = "";
    }
    else {
        for(vector<time_unit>::const_iterator it = time_units.begin();
                it != time_units.end(); it++) {
            
            if(it + 1 == time_units.end() || bar_interval <= (it+1)->seconds) {
                parent.x_label = ssprintf("%d %s intervals", bar_interval / it->seconds, it->name.c_str());
                break;
            }

        }
    }
}

plot::ticks_t time_histogram::build_tick_labels(const render_vars &vars)
{
    plot::ticks_t ticks;

    // y ticks (packet count)

    // scale raw bucket totals

    si_prefix unit = si_prefixes.at(vars.unit_log_1000);
    double y_scale_range = vars.greatest_bucket_sum / (double) unit.magnitude;
    double y_scale_interval = y_scale_range / (y_tick_count - 1);

    for(int ii = 0; ii < y_tick_count; ii++) {
        double raw_value = (y_tick_count - (ii + 1)) * y_scale_interval;
        uint64_t value = (uint64_t) floor(raw_value + 0.5);

        std::string label = ssprintf("%d%s", value, unit.prefix.c_str());

	ticks.y_labels.push_back(label);
    }

    return ticks;
}

void time_histogram::render_bars(cairo_t *cr, const plot::bounds_t &bounds,
        render_vars &vars)
{
#ifdef CAIRO_PDF_AVAILABLE
    cairo_matrix_t original_matrix;

    cairo_get_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    double offset_unit = bounds.width / vars.num_sig_buckets;
    double bar_width = offset_unit / bar_space_factor;
    double space_width = offset_unit - bar_width;
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
            double bar_x = index * offset_unit + space_width;

	    // HTTP (blue)
	    cairo_set_source_rgb(cr, color_http.r, color_http.g,
				 color_http.b);
	    cairo_rectangle(cr, bar_x, current_height, bar_width, http_height);
	    cairo_fill(cr);

	    current_height += http_height;

	    // HTTPS (green)
	    cairo_set_source_rgb(cr, color_https.r, color_https.g,
				 color_https.b);
	    cairo_rectangle(cr, bar_x, current_height, bar_width, https_height);
	    cairo_fill(cr);

	    current_height += https_height;

	    // other (yellow)
	    cairo_set_source_rgb(cr, color_other.r, color_other.g,
				 color_other.b);
	    cairo_rectangle(cr, bar_x, current_height, bar_width, other_height);
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

dyn_time_histogram::dyn_time_histogram() :
    parent(), histograms()
{
    for(int ii = time_histogram::MINUTE; ii <= time_histogram::YEAR; ii++) {
	histograms.push_back(time_histogram((time_histogram::span_t) ii));
    }
}

void dyn_time_histogram::colorize(const plot::rgb_t &color_http_, const plot::rgb_t &color_https_,
        const plot::rgb_t &color_other_)
{
    for(vector<time_histogram>::iterator histogram = histograms.begin();
            histogram != histograms.end(); histogram++) {
        histogram->color_http = color_http_;
        histogram->color_https = color_https_;
        histogram->color_other = color_other_;
    }
}

void dyn_time_histogram::ingest_packet(const packet_info &pi, const struct tcp_seg *optional_tcp)
{
    for(vector<time_histogram>::iterator histogram = histograms.begin();
            histogram != histograms.end(); histogram++) {
        histogram->ingest_packet(pi, optional_tcp);
    }
}

void dyn_time_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
{
    time_histogram best_fit = select_best_fit();

    best_fit.parent = parent;

    best_fit.render(cr, bounds);
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

std::vector<time_histogram::si_prefix> time_histogram::build_si_prefixes()
{
    std::vector<si_prefix> output;

    output.push_back(si_prefix("", 1L));
    output.push_back(si_prefix("K", 1000L));
    output.push_back(si_prefix("M", 1000L * 1000L));
    output.push_back(si_prefix("G", 1000L * 1000L * 1000L));
    output.push_back(si_prefix("T", 1000L * 1000L * 1000L * 1000L));
    output.push_back(si_prefix("P", 1000L * 1000L * 1000L * 1000L * 1000L));
    output.push_back(si_prefix("E", 1000L * 1000L * 1000L * 1000L * 1000L * 1000L));

    return output;
}

std::vector<time_histogram::time_unit> time_histogram::build_time_units()
{
    std::vector<time_unit> output;

    output.push_back(time_unit("second", 1L));
    output.push_back(time_unit("minute", 60L));
    output.push_back(time_unit("hour", 60L * 60L));
    output.push_back(time_unit("day", 60L * 60L * 24L));
    output.push_back(time_unit("week", 60L * 60L * 24L * 7L));
    output.push_back(time_unit("month", 60L * 60L * 24L * 30L));
    output.push_back(time_unit("year", 60L * 60L * 24L * 365L));

    return output;
}
