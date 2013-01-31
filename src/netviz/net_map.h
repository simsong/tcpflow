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
