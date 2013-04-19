/**
 * port_histogram_view.cpp: 
 * Show packets received vs port
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"

#ifdef HAVE_LIBCAIRO
#include "tcpflow.h"

#include "port_histogram_view.h"

#include <math.h>

using namespace std;

port_histogram_view::port_histogram_view(port_histogram &histogram_,
        const map<in_port_t, rgb_t> &color_map_, const rgb_t &default_color_,
        const rgb_t &cdf_color_) :
    histogram(histogram_), color_map(color_map_), default_color(default_color_),
    cdf_color(cdf_color_)
{
    subtitle = "";
    title_on_bottom = true;
    pad_left_factor = 0.1;
    pad_right_factor = 0.1;
    x_label = "";
    y_label = "";
    y_tick_font_size = 6.0;
    right_tick_font_size = 6.0;
}

const double port_histogram_view::bar_space_factor = 1.2;
const double port_histogram_view::bar_chip_size_factor = 0.04;
const double port_histogram_view::cdf_line_width = 0.5;
const double port_histogram_view::data_width_factor = 0.95;

void port_histogram_view::render(cairo_t *cr, const plot_view::bounds_t &bounds)
{
    y_tick_labels.push_back(plot_view::pretty_byte_total(0));
    if(histogram.size() > 0) {
        y_tick_labels.push_back(plot_view::pretty_byte_total(histogram.at(0).count, 0));
    }

    right_tick_labels.push_back("0%");
    right_tick_labels.push_back("100%");

    plot_view::render(cr, bounds);
}

void port_histogram_view::render_data(cairo_t *cr, const plot_view::bounds_t &bounds)
{
    if(histogram.size() < 1 || histogram.at(0).count == 0) {
        return;
    }

    double data_width = bounds.width * data_width_factor;
    double data_offset = 0;
    bounds_t data_bounds(bounds.x + data_offset, bounds.y,
            data_width, bounds.height);

    double visibility_chip_height = data_bounds.height * bar_chip_size_factor;
    double offset_unit = data_bounds.width / histogram.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = (offset_unit - bar_width) / 2.0;
    uint64_t greatest = histogram.at(0).count;
    unsigned int index = 0;

    double cdf_last_x = bounds.x, cdf_last_y = bounds.y + data_bounds.height;
    for(vector<port_histogram::port_count>::const_iterator it = histogram.begin();
            it != histogram.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * data_bounds.height;

        // bar
        double bar_x = data_bounds.x + (index * offset_unit + space_width);
        double bar_y = data_bounds.y + (data_bounds.height - bar_height);
        bounds_t bar_bounds(bar_x, bar_y, bar_width, bar_height);

        rgb_t bar_color = default_color;
        map<in_port_t, rgb_t>::const_iterator color = color_map.find(it->port);
        if(color != color_map.end()) {
            bar_color = color->second;
        }

        bucket_view view(*it, bar_color);

        if(bar_height < visibility_chip_height && bar_color != default_color) {
            view.chip_height = visibility_chip_height;
            view.chip_offset = visibility_chip_height * 0.6;
        }

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
    for(vector<port_histogram::port_count>::const_iterator it = histogram.begin();
            it != histogram.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * data_bounds.height;

        double bar_x = data_bounds.x + (index * offset_unit + space_width);
        double bar_y = data_bounds.y + (data_bounds.height - bar_height);
        bounds_t bar_bounds(bar_x, bar_y, bar_width, bar_height);

        // bar label
        bucket_view view(*it, default_color);
        view.render_label(cr, bar_bounds);

	index++;
    }
}

port_histogram &port_histogram_view::get_data()
{
    return histogram;
}

// bucket view

const double port_histogram_view::bucket_view::label_font_size = 6.0;
const double port_histogram_view::bucket_view::chip_width_factor = 0.4;

void port_histogram_view::bucket_view::render(cairo_t *cr, const bounds_t &bounds)
{
    cairo_set_source_rgb(cr, color.r, color.g, color.b);
    cairo_rectangle(cr, bounds.x, bounds.y, bounds.width, bounds.height);
    cairo_fill(cr);
    if(chip_height > 0.0) {
        double chip_x = bounds.x + (bounds.width * ((1.0 - chip_width_factor) / 2.0));
        double chip_y = bounds.y + bounds.height + chip_offset;
        double chip_width = bounds.width * chip_width_factor;

        cairo_rectangle(cr, chip_x, chip_y, chip_width, chip_height);
        cairo_fill(cr);
    }
}

void port_histogram_view::bucket_view::render_label(cairo_t *cr, const bounds_t &bounds)
{
    cairo_matrix_t unrotated_matrix;
    cairo_get_matrix(cr, &unrotated_matrix);
    cairo_rotate(cr, -M_PI / 4.0);

    cairo_set_font_size(cr, label_font_size);
    string label = ssprintf("%d", bucket.port);

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
