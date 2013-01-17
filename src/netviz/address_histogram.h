#ifndef ADDRESSHISTOGRAM_H
#define ADDRESSHISTOGRAM_H

#include "render.h"
#include "plot.h"

#include "iptree.h"

class address_histogram {
public:
    address_histogram() :
        parent(), bar_space_factor(1.2), bar_count(10), bar_color(0.0, 0.0, 0.0),
        bar_label_font_size(8.0),
        top_addrs(), datagrams_ingested() {}

    void render(cairo_t *cr, const plot::bounds_t &bounds);
    void render_bars(cairo_t *cr, const plot::bounds_t &bounds);
    void from_iptree(const iptree &tree);
    void get_top_addrs(std::vector<iptree::addr_elem> &addr_list);
    uint64_t get_ingest_count();
    void quick_config(const std::string &title_, const plot::rgb_t &bar_color_);

    class iptree_node_comparator {
    public:
        bool operator()(const iptree::addr_elem &a, const iptree::addr_elem &b);
    };

    plot parent;
    double bar_space_factor;
    int bar_count;
    plot::rgb_t bar_color;
    double bar_label_font_size;

private:
    std::vector<iptree::addr_elem> top_addrs;
    uint64_t datagrams_ingested;
};

#endif
