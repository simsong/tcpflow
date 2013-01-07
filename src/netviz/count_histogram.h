#ifndef COUNT_HISTOGRAM_H
#define COUNT_HISTOGRAM_H

#include "render.h"
#include "plot.h"

class count_histogram {
public:
    typedef std::pair<std::string, uint64_t> count_pair;

    count_histogram() :
        parent_plot(), bar_space_factor(1.2), max_bars(10),
        bar_color(0.05, 0.33, 0.65),
        counts() {};

    void increment(std::string key, uint64_t delta);
    void render(cairo_t *cr, const plot::bounds_t &bounds);
    void render_bars(cairo_t *cr, const plot::bounds_t &bounds, const std::vector<count_pair> &bars);
    std::vector<count_pair> build_port_list();

    plot parent_plot;
    double bar_space_factor;
    int max_bars;
    plot::rgb_t bar_color;

    class count_comparator {
    public:
        bool operator()(const count_pair &a, const count_pair &b);
    };

private:
    std::map<std::string, uint64_t> counts;
};

#endif
