#ifndef ADDRESSHISTOGRAM_H
#define ADDRESSHISTOGRAM_H

#include "render.h"
#include "plot.h"
#include "count_histogram.h"

#include "iptree.h"

class address_histogram {
public:
    typedef enum {
        SOURCE = 0, DESTINATION, SRC_OR_DST
    } relationship_t;

    address_histogram() :
        parent_count_histogram(), relationship(SRC_OR_DST) {}

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);
    void render_iptree(cairo_t *cr, const plot::bounds_t &bounds, const iptree &tree);
    void quick_config(relationship_t relationship_, std::string title_,
            std::string subtitle_);

    class iptree_node_comparator {
    public:
        bool operator()(const iptree::addr_elem &a, const iptree::addr_elem &b);
    };

    count_histogram parent_count_histogram;
    relationship_t relationship;
};

#endif
