/**
 * packetfall.cpp: 
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

#include "packetfall.h"

void packetfall::ingest_packet(const be13::packet_info &pi)
{
}

void packetfall::render(cairo_t *cr, const plot_view::bounds_t &bounds)
{
    cairo_set_source_rgb(cr, 0.67, 0.67, 0.67);
    cairo_rectangle(cr, bounds.x, bounds.y, bounds.width, bounds.height);
    cairo_fill(cr);

    double font_size = 16.0;
    std::string label = "pretty packetfall";
    cairo_text_extents_t extents;

    cairo_set_font_size(cr, font_size);
    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);

    cairo_text_extents(cr, label.c_str(), &extents);

    double text_x = bounds.x + (bounds.width - extents.width) / 2.0;
    double text_y = bounds.y + (bounds.height + extents.height) / 2.0;

    cairo_move_to(cr, text_x, text_y);
    cairo_show_text(cr, label.c_str());

}
#endif
