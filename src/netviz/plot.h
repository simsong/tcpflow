#ifndef PLOT_H
#define PLOT_H

#include "render.h"

class plot {
private:
    plot() {}  // static class
public:
    class rgb_t {
    public:
        rgb_t(const double r_, const double g_, const double b_) :
        r(r_), g(g_), b(b_) {}
        double r;
        double g;
        double b;
    };

    class ticks_t {
    public:
        ticks_t() :
        x_labels(), y_labels() {}
        std::vector<std::string> x_labels;
        std::vector<std::string> y_labels;
    };

    class legend_entry_t {
    public:
        legend_entry_t(const rgb_t color_, const std::string label_) :
        color(color_), label(label_) {}
        rgb_t color;
        std::string label;
    };
    typedef std::vector<legend_entry_t> legend_t;

    class config_t {
    public:
        const char *filename;
        const char *title;
        const char *subtitle;
        // width and height are in pt
        double width;
        double height;
        double title_font_size;
        // Title text will be shrunk if needed such that it takes up no more
        // than this ratio of the image width
        double title_max_width_ratio;
        // multiple of title height to be allocated above graph
        double title_y_pad_factor;
        // multiple of the subtitle height that will separate the subtitle from
        // the title
        double subtitle_y_pad_factor;
        // multiple of the title font size for the subtitle font size
        double subtitle_font_size_factor;
        // size of scale ticks, in pt
        double tick_length_factor;
        double tick_width_factor;
        int x_tick_count;
        int y_tick_count;
        int x_tick_label_max_len;
        int y_tick_label_max_len;
        // multiple of label dummy text length to allocate for spacing
        double x_tick_label_pad_factor;
        double y_tick_label_pad_factor;
        double y_tick_font_size;
        double x_tick_font_size;
        // non-dynamic padding for the right and bottom of graph
        double pad_bottom_factor;
        double pad_right_factor;
        // legend
        double legend_chip_factor;
        double legend_font_size;
    };

    class bounds_t {
    public:
        bounds_t() :
            x(0.0), y(0.0), width(0.0), height(0.0) {}
        bounds_t(const double x_, const double y_, const double width_,
                const double height_) :
            x(x_), y(y_), width(width_), height(height_) {}
        double x;
        double y;
        double width;
        double height;
    };

    static const config_t default_config;

    static void render(cairo_t *cr, const bounds_t &bounds,
            const ticks_t &ticks, const legend_t &legend, const config_t &conf,
            bounds_t &content_bounds);
};

#endif
