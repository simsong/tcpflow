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
    histogram(histogram_), bar_color(0.0, 0.0, 0.0)
{
    subtitle = "";
    title_on_bottom = true;
    pad_left_factor = 0.0;
    pad_right_factor = 0.2;
    pad_top_factor = 0.5;
    x_label = "";
    y_label = "";
}

const double address_histogram_view::bar_space_factor = 1.2;

void address_histogram_view::render_data(cairo_t *cr, const bounds_t &bounds)
{
    if(histogram.size() < 1 || histogram.at(0).count == 0) {
        return;
    }

    double offset_unit = bounds.width / histogram.size();
    double bar_width = offset_unit / bar_space_factor;
    double space_width = offset_unit - bar_width;
    uint64_t greatest = histogram.at(0).count;
    int index = 0;

    for(vector<iptree::addr_elem>::const_iterator it = histogram.begin();
            it != histogram.end(); it++) {
	double bar_height = (((double) it->count) / ((double) greatest)) * bounds.height;

	if(bar_height > 0) {
            // bar
            double bar_x = bounds.x + (index * offset_unit + space_width);
            double bar_y = bounds.y + (bounds.height - bar_height);

            bucket_view view(*it, bar_color);
            view.render(cr, bounds_t(bar_x, bar_y, bar_width, bar_height));
	}
	index++;
    }
}

const address_histogram &address_histogram_view::get_data() const
{
    return histogram;
}

// bucket view

const double address_histogram_view::bucket_view::label_font_size = 6.0;

void address_histogram_view::bucket_view::render(cairo_t *cr, const bounds_t &bounds)
{
    cairo_set_source_rgb(cr, color.r, color.g, color.b);
    cairo_rectangle(cr, bounds.x, bounds.y, bounds.width, bounds.height);
    cairo_fill(cr);

    string label = bucket.str();

    // IP6 labels are half size since they're (potentially) much longer
    if(bucket.is4()) {
        cairo_set_font_size(cr, label_font_size);
    }
    else {
        cairo_set_font_size(cr, label_font_size / 2.0);
    }

    cairo_text_extents_t label_extents;
    cairo_text_extents(cr, label.c_str(), &label_extents);

    cairo_move_to(cr, bounds.x + bounds.width / 2.0, bounds.y);

    cairo_matrix_t unrotated_matrix;
    cairo_get_matrix(cr, &unrotated_matrix);
    cairo_rotate(cr, -M_PI / 4.0);

    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_show_text(cr, label.c_str());

    cairo_set_matrix(cr, &unrotated_matrix);
}

#endif
