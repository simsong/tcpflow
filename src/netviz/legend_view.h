/*
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 */


#ifndef LEGEND_VIEW_H
#define LEGEND_VIEW_H

#include "plot_view.h"

class legend_view {
public:
    // legend_view::entry to everyone else
    class entry_t {
    public:
        entry_t(plot_view::rgb_t color_, std::string label_, uint16_t port_) :
            color(color_), label(label_), port(port_) {}
        plot_view::rgb_t color;
        std::string label;
        uint16_t port;
    };
    typedef std::vector<entry_t> entries_t;

    legend_view(entries_t entries_) :
        entries(entries_) {}

    void render(cairo_t *cr, const plot_view::bounds_t &bounds) const;

    static const std::string empty_legend_label;
    static const double base_font_size;
    static const double chip_length;
    static const double chip_label_space;
    static const double inter_item_space;
    static const double padding;
    static const double border_width;
    static const plot_view::rgb_t border_color;
private:
    const entries_t entries;
};

inline bool operator<(const legend_view::entry_t &a, const legend_view::entry_t &b)
{
    return a.port < b.port;
}
#endif
