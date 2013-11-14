/*
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 */


#ifndef ADDRESS_HISTOGRAM_VIEW_H
#define ADDRESS_HISTOGRAM_VIEW_H

#include "config.h"
#ifdef HAVE_LIBCAIRO

#include "plot_view.h"
#include "address_histogram.h"

class address_histogram_view : public plot_view {
public:
    address_histogram_view(const address_histogram &histogram_);

    class bucket_view {
    public:
        bucket_view(const iptree::addr_elem &bucket_,
                const rgb_t &color_) :
            bucket(bucket_), color(color_) {}

        const iptree::addr_elem &bucket;
        const rgb_t &color;

        static const double label_font_size;

        void render(cairo_t *cr, const bounds_t &bounds);
        void render_label(cairo_t *cr, const bounds_t &bounds);
    };

    const address_histogram &histogram;
    rgb_t bar_color;
    rgb_t cdf_color;

    static const double bar_space_factor;
    static const size_t compressed_ip6_str_max_len;
    static const double cdf_line_width;
    static const double data_width_factor;

    void render(cairo_t *cr, const bounds_t &bounds);
    void render_data(cairo_t *cr, const bounds_t &bounds);
    const address_histogram &get_data() const;

    static std::string compressed_ip6_str(iptree::addr_elem address);
};

#endif
#endif
