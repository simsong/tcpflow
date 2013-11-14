/**
 * net_map.h: 
 * Show map of network traffic by host
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#ifndef NET_MAP_H
#define NET_MAP_H

#include "plot_view.h"

class net_map {
public:
    net_map() {}

    void ingest_packet(const be13::packet_info &pi);
    void render(cairo_t *cr, const plot_view::bounds_t &bounds);
};

#endif
