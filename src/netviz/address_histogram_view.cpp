/**
 * address_histogram_view.cpp: 
 * Show packets received vs addr
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"

#ifdef HAVE_LIBCAIRO
#include "tcpflow.h"

#include <math.h>
#include <iomanip>

#include "address_histogram_view.h"

using namespace std;

address_histogram_view::address_histogram_view(const address_histogram &histogram_) :
    histogram(histogram_), bar_color(0.0, 0.0, 0.0), cdf_color(0.0, 0.0, 0.0)
{
    subtitle = "";
    title_on_bottom = true;
    pad_left_factor = 0.1;
    pad_right_factor = 0.1;
    pad_top_factor = 0.5;
    x_label = "";
    y_label = "";
    y_tick_font_size = 6.0;
    right_tick_font_size = 6.0;
}

const double address_histogram_view::bar_space_factor = 1.2;
const size_t address_histogram_view::compressed_ip6_str_max_len = 16;
const double address_histogram_view::cdf_line_width = 0.5;
const double address_histogram_view::data_width_factor = 0.85;

void address_histogram_view::render(cairo_t *cr, const bounds_t &bounds)
{
    y_tick_labels.push_back(plot_view::pretty_byte_total(0));
    if(histogram.size() > 0) {
        y_tick_labels.push_back(plot_view::pretty_byte_total(histogram.at(0).count, 0));
    }

    right_tick_labels.push_back("0%");
    right_tick_labels.push_back("100%");

    plot_view::render(cr, bounds);
}

void address_histogram_view::render_data(cairo_t *cr, const bounds_t &bounds)
{
    if(histogram.size() < 1 || histogram.at(0).count == 0) {
        return;
    }

    double data_width = bounds.width * data_width_factor;
    double data_offset = 0;
    bounds_t data_bounds(bounds.x + data_offset, bounds.y,
            data_width, bounds.height);

    double offset_unit = data_bounds.width / histogram.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = (offset_unit - bar_width) / 2.0;
    uint64_t greatest = histogram.at(0).count;
    unsigned int index = 0;

    double cdf_last_x = bounds.x, cdf_last_y = bounds.y + data_bounds.height;
    for(address_histogram::ipt_addrs::const_iterator it = histogram.begin();
            it != histogram.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * data_bounds.height;

        // bar
        double bar_x = data_bounds.x + (index * offset_unit + space_width);
        double bar_y = data_bounds.y + (data_bounds.height - bar_height);
        bounds_t bar_bounds(bar_x, bar_y, bar_width, bar_height);

        bucket_view view(*it, bar_color);
        view.render(cr, bar_bounds);

        // CDF
        double cdf_x = cdf_last_x + offset_unit;
        // account for left and right padding of bars
        if(index == 0) {
            cdf_x += data_offset;
        }
        if(index == histogram.size() - 1) {
            cdf_x = bounds.x + bounds.width;
        }
        double cdf_y = cdf_last_y - ((double) it->count / (double) histogram.ingest_count()) *
                data_bounds.height;

        cairo_move_to(cr, cdf_last_x, cdf_last_y);
        // don't draw over the left-hand y axis
        if(index == 0) {
            cairo_move_to(cr, cdf_last_x, cdf_y);
        }
        else {
            cairo_line_to(cr, cdf_last_x, cdf_y);
        }
        cairo_line_to(cr, cdf_x, cdf_y);

        cairo_set_source_rgb(cr, cdf_color.r, cdf_color.g, cdf_color.b);
        cairo_set_line_width(cr, cdf_line_width);
        cairo_stroke(cr);

        cdf_last_x = cdf_x;
        cdf_last_y = cdf_y;

	index++;
    }
    index = 0;
    // labels must be done after the fact to avoid awkward interaction with the CDF
    for(address_histogram::ipt_addrs::const_iterator it = histogram.begin();
            it != histogram.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * data_bounds.height;
        double bar_x = data_bounds.x + (index * offset_unit + space_width);
        double bar_y = data_bounds.y + (data_bounds.height - bar_height);
        bounds_t bar_bounds(bar_x, bar_y, bar_width, bar_height);
        bucket_view view(*it, bar_color);
        view.render_label(cr, bar_bounds);
        index++;
    }
}

const address_histogram &address_histogram_view::get_data() const
{
    return histogram;
}

string address_histogram_view::compressed_ip6_str(iptree::addr_elem address)
{
    return ssprintf("%x:%x...%x", (address.addr[0] << 8) + address.addr[1],
            (address.addr[2] << 8) + address.addr[3],
            (address.addr[14] << 8) + address.addr[15]);
}

// bucket view

const double address_histogram_view::bucket_view::label_font_size = 6.0;

void address_histogram_view::bucket_view::render(cairo_t *cr, const bounds_t &bounds)
{
    cairo_set_source_rgb(cr, color.r, color.g, color.b);
    cairo_rectangle(cr, bounds.x, bounds.y, bounds.width, bounds.height);
    cairo_fill(cr);
}

void address_histogram_view::bucket_view::render_label(cairo_t *cr, const bounds_t &bounds)
{
    cairo_matrix_t unrotated_matrix;
    cairo_get_matrix(cr, &unrotated_matrix);
    cairo_rotate(cr, -M_PI / 4.0);

    string label = bucket.str();
    if(!bucket.is4() && label.length() > compressed_ip6_str_max_len) {
        label = compressed_ip6_str(bucket);
    }

    cairo_set_font_size(cr, label_font_size);

    cairo_text_extents_t label_extents;
    cairo_text_extents(cr, label.c_str(), &label_extents);

    double label_x = bounds.x + bounds.width / 2.0;
    double label_y = bounds.y - 2.0;
    cairo_device_to_user(cr, &label_x, &label_y);

    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_rectangle(cr, label_x, label_y, label_extents.width, -label_extents.height);
    cairo_fill(cr);
    cairo_rectangle(cr, label_x, label_y, label_extents.width, -label_extents.height);
    cairo_set_line_width(cr, 2.0);
    cairo_stroke(cr);

    cairo_move_to(cr, label_x, label_y);

    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_show_text(cr, label.c_str());

    cairo_set_matrix(cr, &unrotated_matrix);
}

#endif
