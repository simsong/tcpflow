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

#ifdef CAIRO_PDF_AVAILABLE
#include "tcpflow.h"
#include "tcpip.h"

#include <math.h>
#include <iomanip>
#include <algorithm>

#include "address_histogram.h"

void address_histogram::render(cairo_t *cr, const plot::bounds_t &bounds)
{
    plot::ticks_t ticks;
    plot::legend_t legend;
    plot::bounds_t content_bounds(0.0, 0.0, bounds.width,
            bounds.height);
    //// have the plot class do labeling, axes, legend etc
    parent.render(cr, bounds, ticks, legend, content_bounds);

    //// fill borders rendered by plot class
    render_bars(cr, content_bounds);
}

void address_histogram::render_bars(cairo_t *cr, const plot::bounds_t &bounds)
{
    if(top_addrs.size() < 1 || top_addrs.at(0).count == 0) {
        return;
    }

    cairo_matrix_t original_matrix;

    cairo_get_matrix(cr, &original_matrix);
    cairo_translate(cr, bounds.x, bounds.y);

    double offset_unit = bounds.width / top_addrs.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = offset_unit - bar_width;
    uint64_t greatest = top_addrs.at(0).count;
    int index = 0;

    for(vector<iptree::addr_elem>::const_iterator it = top_addrs.begin();
            it != top_addrs.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * bounds.height;

	if(bar_height > 0) {
            // bar
            double bar_x = index * offset_unit + space_width;
            double bar_y = bounds.height - bar_height;

            cairo_set_source_rgb(cr, bar_color.r, bar_color.g, bar_color.b);
            cairo_rectangle(cr, bar_x, bar_y, bar_width, bar_height);
            cairo_fill(cr);

            // bar label
            std::string label = it->str();

            // IP6 labels are half size since they're (potentially) much longer
            if(it->is4()) {
                cairo_set_font_size(cr, bar_label_font_size);
            }
            else {
                cairo_set_font_size(cr, bar_label_font_size / 2.0);
            }

            cairo_text_extents_t label_extents;
            cairo_text_extents(cr, label.c_str(), &label_extents);

            cairo_move_to(cr, bar_x + bar_width / 2.0, bar_y);

            cairo_matrix_t unrotated_matrix;
            cairo_get_matrix(cr, &unrotated_matrix);
            cairo_rotate(cr, -M_PI / 4.0);

            cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
            cairo_show_text(cr, label.c_str());

            cairo_set_matrix(cr, &unrotated_matrix);
	}
	index++;
    }

    cairo_set_matrix(cr, &original_matrix);
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
    parent.pad_right_factor = 0.2;
    parent.pad_top_factor = 0.5;
    parent.x_label = "";
    parent.y_label = "";
}
#endif
