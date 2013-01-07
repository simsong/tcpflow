#ifndef PORTHISTOGRAM_H
#define PORTHISTOGRAM_H

#include "render.h"
#include "plot.h"

class port_histogram {
public:
    typedef enum {
        SENDER = 0, RECEIVER, SND_OR_RCV
    } relationship_t;
    typedef std::pair<uint16_t, uint64_t> count_pair;

    port_histogram() :
        parent(), relationship(SND_OR_RCV), bar_space_factor(1.2), max_bars(10),
        bar_color(0.05, 0.33, 0.65),
        port_counts() {};

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);
    void render_bars(cairo_t *cr, const plot::bounds_t &bounds, const std::vector<count_pair> &bars);
    std::vector<count_pair> build_port_list();

    plot parent;
    relationship_t relationship;
    double bar_space_factor;
    int max_bars;
    plot::rgb_t bar_color;

    class count_comparator {
    public:
        bool operator()(const count_pair &a, const count_pair &b);
    };

private:
    std::map<uint16_t, uint64_t> port_counts;
};

#endif
