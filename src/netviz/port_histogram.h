#ifndef PORTHISTOGRAM_H
#define PORTHISTOGRAM_H

#include "render.h"
#include "plot.h"

class one_page_report;

class port_histogram {
public:
    typedef enum {
        SOURCE = 0, DESTINATION, SRC_OR_DST
    } relationship_t;

    class port_count {
    public:
        port_count() : port(0), count(0) {}
        port_count(uint16_t port_, uint64_t count_) :
            port(port_), count(count_) {}
        uint16_t port;
        uint64_t count;
    };

    class descending_counts {
    public:
        bool operator()(const port_count &a, const port_count &b);
    };

    port_histogram() :
        parent(), relationship(SRC_OR_DST), bar_space_factor(1.2), bar_count(10),
        bar_label_font_size(8.0),
        port_counts(), segments_ingested(), top_ports_cache(), top_ports_dirty(true) {}

    void ingest_segment(const struct tcp_seg &tcp);
    void render(cairo_t *cr, const plot::bounds_t &bounds, const one_page_report &report);
    void render_bars(cairo_t *cr, const plot::bounds_t &bounds, const one_page_report &report);
    void get_top_ports(std::vector<port_count> &top_ports);
    void quick_config(const relationship_t &relationship_, const std::string &title_);
    uint64_t get_ingest_count();

    plot parent;
    relationship_t relationship;
    double bar_space_factor;
    int bar_count;
    double bar_label_font_size;

private:
    std::map<uint16_t, uint64_t> port_counts;
    uint64_t segments_ingested;
    std::vector<port_count> top_ports_cache;
    bool top_ports_dirty;
};

#endif
