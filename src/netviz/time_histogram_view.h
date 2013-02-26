#ifndef TIME_HISTOGRAM_VIEW_H
#define TIME_HISTOGRAM_VIEW_H

#include "config.h"
#ifdef HAVE_LIBCAIRO

#include "plot_view.h"
#include "time_histogram.h"

class time_histogram_view : public plot_view {
public:
    time_histogram_view(const time_histogram &histogram_,
            const std::map<time_histogram::port_t, rgb_t> &port_colors_,
            const rgb_t &default_color_, const rgb_t &cdf_color_);

    class time_unit {
    public:
        time_unit(std::string name_, uint64_t seconds_) :
            name(name_), seconds(seconds_) {}
        std::string name;
        uint64_t seconds;
    };
    class si_prefix {
    public:
        si_prefix(std::string prefix_, uint64_t magnitude_) :
            prefix(prefix_), magnitude(magnitude_) {}
        std::string prefix;
        uint64_t magnitude;
    };
    class bucket_view {
    public:
        bucket_view(const time_histogram::bucket &bucket_,
                const std::map<time_histogram::port_t, rgb_t> &color_map_,
                const rgb_t &default_color_) :
            bucket(bucket_), color_map(color_map_), default_color(default_color_) {}

        const time_histogram::bucket &bucket;
        const std::map<time_histogram::port_t, rgb_t> &color_map;
        const rgb_t &default_color;

        void render(cairo_t *cr, const bounds_t &bounds);
    };

    const time_histogram &histogram;
    const std::map<time_histogram::port_t, rgb_t> port_colors;
    const rgb_t default_color;
    const rgb_t cdf_color;

    static const uint8_t y_tick_count;
    static const double bar_space_factor;
    static const double cdf_line_width;
    static const std::vector<time_unit> time_units;
    static const std::vector<si_prefix> si_prefixes;

    void render(cairo_t *cr, const bounds_t &bounds);
    void render_data(cairo_t *cr, const bounds_t &bounds);

    static std::vector<time_unit> build_time_units();
    static std::vector<si_prefix> build_si_prefixes();
};

#endif
#endif
