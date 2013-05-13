/**
 * legend_view.cpp: 
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

#include "legend_view.h"

using namespace std;

const string legend_view::empty_legend_label = "No TCP";
const double legend_view::base_font_size = 6.0;
const double legend_view::chip_length = 8.0;
const double legend_view::chip_label_space = 4.0;
const double legend_view::inter_item_space = 12.0;
const double legend_view::padding = 8.0;
const double legend_view::border_width = 0.5;
const plot_view::rgb_t legend_view::border_color(0.67, 0.67, 0.67);

void legend_view::render(cairo_t *cr, const plot_view::bounds_t &bounds) const
{
    double font_size = base_font_size;
    if(entries.size() == 0) {
        font_size *= 2.0;
    }
    cairo_set_font_size(cr, font_size);

    double tallest = 0.0;
    double total_width = 0.0;
    for(entries_t::const_iterator it = entries.begin(); it != entries.end(); ++it) {
        cairo_text_extents_t extents;
        cairo_text_extents(cr, it->label.c_str(), &extents);
        total_width += chip_length + chip_label_space + extents.width;
        if(it + 1 != entries.end()) {
            total_width += inter_item_space;
        }
        if(extents.height > tallest) {
            tallest = extents.height;
        }
    }
    if(entries.size() == 0) {
        cairo_text_extents_t extents;
        cairo_text_extents(cr, empty_legend_label.c_str(), &extents);
        total_width += extents.width;
        tallest = extents.height;
    }

    double chip_y = bounds.y + ((bounds.height - chip_length) / 2.0);
    double label_y = bounds.y + ((bounds.height + tallest) / 2.0);
    double x = bounds.x + ((bounds.width - total_width) / 2.0);

    cairo_set_source_rgb(cr, border_color.r, border_color.g, border_color.b);
    cairo_set_line_width(cr, border_width);
    cairo_rectangle(cr, x, bounds.y, total_width + (padding * 2.0), bounds.height);
    cairo_stroke(cr);

    x += padding;

    for(entries_t::const_iterator it = entries.begin(); it != entries.end(); ++it) {
        cairo_text_extents_t extents;
        cairo_text_extents(cr, it->label.c_str(), &extents);

        const plot_view::rgb_t &color = it->color;
        cairo_set_source_rgb(cr, color.r, color.g, color.b);
        cairo_rectangle(cr, x, chip_y, chip_length, chip_length);
        cairo_fill(cr);

        x += chip_length + chip_label_space;

        cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
        cairo_move_to(cr, x, label_y);
        cairo_show_text(cr, it->label.c_str());
        x += extents.width + inter_item_space;
    }
    if(entries.size() == 0) {
        cairo_text_extents_t extents;
        cairo_text_extents(cr, empty_legend_label.c_str(), &extents);

        cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
        cairo_move_to(cr, x, label_y);
        cairo_show_text(cr, empty_legend_label.c_str());
        x += extents.width + inter_item_space;
    }
}
#endif
