#ifndef PORT_HISTOGRAM_VIEW_H
#define PORT_HISTOGRAM_VIEW_H

#include "config.h"
#ifdef HAVE_LIBCAIRO

#include "plot_view.h"
#include "port_histogram.h"

class port_histogram_view : public plot_view {
public:
    port_histogram_view(port_histogram &histogram_,
            const std::map<port_histogram::port_t, rgb_t> &color_map_,
            const rgb_t &default_color);

    class bucket_view {
    public:
        bucket_view(const port_histogram::port_count &bucket_,
                const rgb_t &color_) :
            bucket(bucket_), color(color_), chip_height(0.0), chip_offset(0.0) {}

        const port_histogram::port_count &bucket;
        const rgb_t &color;
        double chip_height;
        double chip_offset;

        static const double label_font_size;
        static const double chip_width_factor;

        void render(cairo_t *cr, const bounds_t &bounds);
    };

    port_histogram &histogram;
    const std::map<port_histogram::port_t, rgb_t> &color_map;
    const rgb_t &default_color;

    static const double bar_space_factor;
    static const double bar_chip_size_factor;

    void render(cairo_t *cr, const bounds_t &bounds);
    void render_data(cairo_t *cr, const bounds_t &bounds);
    port_histogram &get_data();
};

#endif
#endif
