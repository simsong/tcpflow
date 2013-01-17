/**
 * address_histogram.cpp: 
 * Show packets received vs addr
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"
#include "tcpflow.h"
#include "tcpip.h"

#include <iomanip>
#include <algorithm>

#include "address_histogram.h"

void address_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
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

void address_histogram::render_bars(cairo_t *cr, const plot::bounds_t &bounds)
{
    if(top_addrs.size() < 1 || top_addrs.at(0).count == 0) {
        return;
    }

#ifdef CAIRO_PDF_AVAILABLE
    cairo_matrix_t original_matrix;

    cairo_get_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    cairo_set_source_rgb(cr, bar_color.r, bar_color.g, bar_color.b);

    double offset_unit = bounds.width / top_addrs.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = offset_unit - bar_width;
    uint64_t greatest = top_addrs.at(0).count;
    int index = 0;

    for(vector<iptree::addr_elem>::const_iterator it = top_addrs.begin();
            it != top_addrs.end(); it++) {
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

// derive histogram from iptree.  This is called by one_page_report just before
// rendering rather than receiving datagrams one-by-one as they arrive
void address_histogram::from_iptree(const iptree &tree)
{
    // convert iptree to suitable vector for count histogram
    std::vector<iptree::addr_elem> addresses;

    tree.get_histogram(addresses);

    std::sort(addresses.begin(), addresses.end(), iptree_node_comparator());

    top_addrs.clear();
    top_addrs.resize(bar_count);

    std::vector<iptree::addr_elem>::const_iterator it = addresses.begin();
    int ii = 0;
    while(ii < bar_count && it != addresses.end()) {
        top_addrs.at(ii) = *it;
        ii++;
        it++;
    }

    datagrams_ingested = tree.sum();
}

void address_histogram::get_top_addrs(std::vector<iptree::addr_elem> &addr_list)
{
    addr_list = top_addrs;
}

uint64_t address_histogram::get_ingest_count()
{
    return datagrams_ingested;
}

bool address_histogram::iptree_node_comparator::operator()(const iptree::addr_elem &a,
        const iptree::addr_elem &b)
{
    if(a.count > b.count) {
        return true;
    }
    else if(a.count < b.count) {
        return false;
    }
    for(size_t ii = 0; ii < sizeof(a.addr); ii++) {
        if(a.addr[ii] > b.addr[ii]) {
            return true;
        }
        else if(a.addr[ii] < b.addr[ii]) {
            return false;
        }
    }
    return false;
}

void address_histogram::quick_config(const std::string &title_, const plot::rgb_t &bar_color_)
{
    bar_color = bar_color_;
    parent.title = title_;
    parent.subtitle = "";
    parent.title_on_bottom = true;
    parent.pad_left_factor = 0.0;
    parent.pad_right_factor = 0.0;
    parent.x_label = "";
    parent.y_label = "";
}
