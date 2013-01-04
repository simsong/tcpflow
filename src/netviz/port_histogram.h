#ifndef PORTHISTOGRAM_H
#define PORTHISTOGRAM_H

#include "render.h"
#include "plot.h"

class port_histogram {
public:
    typedef enum {
        SENDER = 0, RECEIVER, SND_OR_RCV
    } relationship_t;

    port_histogram() :
        parent(), relationship(SND_OR_RCV), bar_space_factor(1.2), max_bars(10),
        port_counts() {};

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);

    plot parent;
    relationship_t relationship;
    double bar_space_factor;
    int max_bars;

private:
    std::map<std::string, uint16_t> port_counts;
};

#endif
