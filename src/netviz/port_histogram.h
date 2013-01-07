#ifndef PORTHISTOGRAM_H
#define PORTHISTOGRAM_H

#include "render.h"
#include "plot.h"
#include "count_histogram.h"

class port_histogram {
public:
    typedef enum {
        SENDER = 0, RECEIVER, SND_OR_RCV
    } relationship_t;

    port_histogram() :
        parent_count_histogram(), relationship(SND_OR_RCV) {}

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);

    count_histogram parent_count_histogram;
    relationship_t relationship;
};

#endif
