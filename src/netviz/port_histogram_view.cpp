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
        const map<port_histogram::port_t, rgb_t> &color_map_, const rgb_t &default_color_) :
    histogram(histogram_), color_map(color_map_), default_color(default_color_)
{
    subtitle = "";
    title_on_bottom = true;
    pad_left_factor = 0.1;
    pad_right_factor = 0.1;
    x_label = "";
    y_label = "";
    y_tick_font_size = 6.0;
}

const double port_histogram_view::bar_space_factor = 1.2;
const double port_histogram_view::bar_chip_size_factor = 0.04;

void port_histogram_view::render(cairo_t *cr, const plot_view::bounds_t &bounds)
{
    y_tick_labels.push_back(plot_view::pretty_byte_total(0));
    if(histogram.size() > 0) {
        y_tick_labels.push_back(plot_view::pretty_byte_total(histogram.at(0).count, 0));
    }

    plot_view::render(cr, bounds);
}

void port_histogram_view::render_data(cairo_t *cr, const plot_view::bounds_t &bounds)
{
    if(histogram.size() < 1 || histogram.at(0).count == 0) {
        return;
    }

    double visibility_chip_height = bounds.height * bar_chip_size_factor;
    double offset_unit = bounds.width / histogram.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = (offset_unit - bar_width) / 2.0;
    uint64_t greatest = histogram.at(0).count;
    int index = 0;

    for(vector<port_histogram::port_count>::const_iterator it = histogram.begin();
            it != histogram.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * bounds.height;

	if(bar_height > 0) {
            // bar
            double bar_x = bounds.x + (index * offset_unit + space_width);
            double bar_y = bounds.y + (bounds.height - bar_height);

            rgb_t bar_color = default_color;
            map<port_histogram::port_t, rgb_t>::const_iterator color = color_map.find(it->port);
            if(color != color_map.end()) {
                bar_color = color->second;
            }

            bucket_view view(*it, bar_color);

            if(bar_height < visibility_chip_height && bar_color != default_color) {
                view.chip_height = visibility_chip_height;
                view.chip_offset = visibility_chip_height * 0.6;
            }

            view.render(cr, bounds_t(bar_x, bar_y, bar_width, bar_height));
	}
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

    string label = ssprintf("%d", bucket.port);

    cairo_text_extents_t label_extents;
    cairo_text_extents(cr, label.c_str(), &label_extents);

    cairo_move_to(cr, bounds.x + bounds.width / 2.0, bounds.y);

    cairo_matrix_t unrotated_matrix;
    cairo_get_matrix(cr, &unrotated_matrix);
    cairo_rotate(cr, -M_PI / 4.0);

    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_set_font_size(cr, label_font_size);
    cairo_show_text(cr, label.c_str());

    cairo_set_matrix(cr, &unrotated_matrix);
}
#endif
