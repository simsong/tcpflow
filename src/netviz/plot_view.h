/**
 * plotview.h:
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */


#ifndef PLOT_VIEW_H
#define PLOT_VIEW_H

#ifdef HAVE_LIBCAIRO
#ifdef HAVE_CAIRO_H
#include <cairo.h>
#elif defined HAVE_CAIRO_CAIRO_H
#include <cairo/cairo.h>
#endif
#ifdef HAVE_CAIRO_PDF_H
#include <cairo-pdf.h>
#elif defined HAVE_CAIRO_CAIRO_PDF_H
#include <cairo/cairo-pdf.h>
#endif

#include <vector>
#include <string>
#include <math.h>

#ifndef M_PI
#define M_PI		3.14159265358979323846
#endif


class plot_view {
public:
    plot_view() :
        title("graph of things"), subtitle("x vs y"),
        x_label("x axis"), y_label("y axis"), x_tick_labels(), y_tick_labels(),
        right_tick_labels(),
        legend(), width(161.803), height(100.000), title_on_bottom(false),
        title_font_size(8.0), x_axis_font_size(8.0), y_axis_font_size(8.0),
        title_max_width_ratio(0.8), title_y_pad_factor(2.0), subtitle_y_pad_factor(0.2),
        subtitle_font_size_factor(0.4), axis_thickness_factor(0.002),
        tick_length_factor(0.0124), tick_width_factor(0.002),
        x_tick_label_pad_factor(4.0), y_tick_label_pad_factor(2.0), right_tick_label_pad_factor(2.0),
        x_tick_font_size(3.0), y_tick_font_size(3.0), right_tick_font_size(3.0), pad_left_factor(0.148),
        pad_top_factor(0.2), pad_bottom_factor(0.2), pad_right_factor(0.148),
        legend_chip_factor(1.2), legend_font_size(2.5),
        x_axis_decoration(AXIS_NO_DECO), y_axis_decoration(AXIS_NO_DECO) {}

    typedef enum {
        AXIS_NO_DECO = 0, AXIS_SPAN_ARROW, AXIS_SPAN_STOP
    } axis_decoration_t;

    class rgb_t {
    public:
        rgb_t() : r(0.0), g(0.0), b(0.0) {}
        rgb_t(const double r_, const double g_, const double b_) :
        r(r_), g(g_), b(b_) {}
        double r;
        double g;
        double b;
        static const double epsilon;    // 1/256.0 (not inline due to -Wgnu)
    };

    class legend_entry_t {
    public:
        legend_entry_t(const rgb_t color_, const std::string label_) :
        color(color_), label(label_) {}
        rgb_t color;
        std::string label;
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

    std::string title, subtitle;
    std::string x_label, y_label;
    std::vector<std::string> x_tick_labels, y_tick_labels, right_tick_labels;
    std::vector<legend_entry_t> legend;
    // width and height are in pt
    double width, height;
    bool title_on_bottom;
    double title_font_size;
    double x_axis_font_size, y_axis_font_size;
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
    // axis scale
    double axis_thickness_factor;
    // size of scale ticks, in pt
    double tick_length_factor, tick_width_factor;
    // multiple of label dummy text length to allocate for spacing
    double x_tick_label_pad_factor, y_tick_label_pad_factor, right_tick_label_pad_factor;
    double x_tick_font_size, y_tick_font_size, right_tick_font_size;
    // non-dynamic padding for the right and bottom of graph
    double pad_left_factor, pad_top_factor, pad_bottom_factor, pad_right_factor;
    // legend
    double legend_chip_factor;
    double legend_font_size;
    // axis decoration
    axis_decoration_t x_axis_decoration, y_axis_decoration;

    static const double text_line_base_width;
    static const double span_arrow_angle;
    static const double span_stop_angle;
    static const std::vector<std::string> size_suffixes;

    virtual ~plot_view() = 0;
    // render everything common to all plots (everything but the data)
    void render(cairo_t *cr, const bounds_t &bounds);
    // called by render(); subclass-specific data rendering
    virtual void render_data(cairo_t *cr, const bounds_t &bounds) = 0;

    // format a byte count for humans ( 12 MB etc)
    static std::string pretty_byte_total(uint64_t byte_count, uint8_t precision);
    static std::string pretty_byte_total(uint64_t byte_count);
    static std::vector<std::string> build_size_suffixes();
};

inline plot_view::~plot_view() {}

inline bool operator==(const plot_view::rgb_t &a, const plot_view::rgb_t &b)
{
    return fabs(a.r - b.r) < plot_view::rgb_t::epsilon &&
        fabs(a.g - b.g) < plot_view::rgb_t::epsilon &&
        fabs(a.b - b.b) < plot_view::rgb_t::epsilon;
}

inline bool operator!=(const plot_view::rgb_t &a, const plot_view::rgb_t &b)
{
    return !(a == b);
}

inline bool operator<(const plot_view::rgb_t &a, const plot_view::rgb_t &b)
{
    return a.r < b.r || a.g < b.g || a.b < b.b;
}

#endif
#endif
