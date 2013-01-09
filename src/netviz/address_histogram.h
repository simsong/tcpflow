#ifndef ADDRESSHISTOGRAM_H
#define ADDRESSHISTOGRAM_H

#include "render.h"
#include "plot.h"
#include "count_histogram.h"

class address_histogram {
public:
    typedef enum {
        SOURCE = 0, DESTINATION, SRC_OR_DST
    } relationship_t;

    address_histogram() :
        parent_count_histogram(), relationship(SRC_OR_DST) {}

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);
    void quick_config(relationship_t relationship_, std::string title_,
            std::string subtitle_);

    count_histogram parent_count_histogram;
    relationship_t relationship;
};

#endif
