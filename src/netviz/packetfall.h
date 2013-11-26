/**
 * packetfall.h: 
 * Show packets received vs port
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#ifndef PACKETFALL_H
#define PACKETFALL_H

#include "plot_view.h"

class packetfall {
public:
    packetfall() {}

    void ingest_packet(const be13::packet_info &pi);
    void render(cairo_t *cr, const plot_view::bounds_t &bounds);
};

#endif
