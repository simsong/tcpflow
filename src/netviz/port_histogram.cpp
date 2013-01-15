/**
 * port_histogram.cpp: 
 * Show packets received vs port
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"
#include "tcpip.h"

#include "port_histogram.h"

#include <algorithm>

bool port_histogram::descending_counts::operator()(const port_count &a,
        const port_count &b)
{
    if(a.count > b.count) {
        return true;
    }
    if(a.count < b.count) {
        return false;
    }
    return a.port < b.port;
}

void port_histogram::ingest_segment(const struct tcp_seg &tcp)
{
    if(relationship == SOURCE || relationship == SRC_OR_DST) {
        port_counts[ntohs(tcp.header->th_sport)]++;
    }
    if(relationship == DESTINATION || relationship == SRC_OR_DST) {
        port_counts[ntohs(tcp.header->th_dport)]++;
    }
}

void port_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
{
#ifdef CAIRO_PDF_AVAILABLE
    plot::ticks_t ticks;
    plot::legend_t legend;
    plot::bounds_t content_bounds(0.0, 0.0, bounds.width,
            bounds.height);
    //// have the plot class do labeling, axes, legend etc
    parent.render(cr, bounds, ticks, legend, content_bounds);

    //// fill borders rendered by plot class
    render_bars(cr, content_bounds);
#endif
}

void port_histogram::render_bars(cairo_t *cr, const plot::bounds_t &bounds)
{
    std::vector<port_count> top_ports;
    get_top_ports(top_ports);

    if(top_ports.size() < 1 || top_ports.at(0).count == 0) {
        return;
    }

#ifdef CAIRO_PDF_AVAILABLE
    cairo_matrix_t original_matrix;

    cairo_get_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);

    double offset_unit = bounds.width / top_ports.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = offset_unit - bar_width;
    uint64_t greatest = top_ports.at(0).count;
    int index = 0;

    for(vector<port_count>::const_iterator it = top_ports.begin();
            it != top_ports.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * bounds.height;

	if(bar_height > 0) {
	    cairo_rectangle(cr, index * offset_unit + space_width, bounds.height - bar_height,
			    bar_width, bar_height);
	    cairo_fill(cr);
	}
	index++;
    }

    cairo_set_matrix(cr, &original_matrix);
#endif
}

void port_histogram::get_top_ports(std::vector<port_count> &top_ports)
{
    top_ports.clear();

    for(std::map<uint16_t, uint64_t>::const_iterator it = port_counts.begin();
            it != port_counts.end(); it++) {
        top_ports.push_back(port_count(it->first, it->second));
    }

    std::sort(top_ports.begin(), top_ports.end(), descending_counts());

    top_ports.resize(bar_count);
}

void port_histogram::quick_config(relationship_t relationship_,
        std::string title_)
{
    relationship = relationship_;
    parent.title = title_;
    parent.subtitle = "";
    parent.title_on_bottom = true;
    parent.pad_left_factor = 0.0;
    parent.pad_right_factor = 0.0;
    parent.x_label = "";
    parent.y_label = "";
}

uint64_t port_histogram::get_ingest_count()
{
    return segments_ingested;
}
