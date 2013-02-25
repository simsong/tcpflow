#ifndef ONE_PAGE_REPORT_H
#define ONE_PAGE_REPORT_H
#include "plot_view.h"
#include "time_histogram.h"
#include "time_histogram_view.h"
#include "address_histogram.h"
#include "address_histogram_view.h"
#include "port_histogram.h"
#include "port_histogram_view.h"
#include "packetfall.h"
#include "net_map.h"
#include "iptree.h"

class one_page_report {
public:
    std::string source_identifier;
    std::string filename;
    plot_view::bounds_t bounds;
    double header_font_size;
    double top_list_font_size;
    unsigned int histogram_show_top_n_text;

    class transport_type {
    public:
        transport_type(uint16_t ethertype_, std::string name_) :
            ethertype(ethertype_), name(name_) {}
        uint16_t ethertype;
        std::string name;
    };
    // a single render event: content moves down a bounded cairo surface as
    // indicated by end_of_content between render method invocations
    class render_pass {
    public:
        render_pass(one_page_report &report_, cairo_t *surface_,
                const plot_view::bounds_t &bounds_) :
            report(report_), surface(surface_), surface_bounds(bounds_),
            end_of_content(0.0) {}

        void render_text_line(std::string text, double font_size,
                double line_space);
        void render_text(std::string text, double font_size, double x_offset,
                cairo_text_extents_t &rendered_extents);

        void render_header();
        void render(time_histogram_view &view);
        void render(address_histogram_view &left, address_histogram_view &right);
        void render(port_histogram_view &left, port_histogram_view &right);
        void render_map();
        void render_packetfall();

        one_page_report &report;
        cairo_t *surface;
        plot_view::bounds_t surface_bounds;
        double end_of_content;
    };
    friend class render_pass;

    one_page_report();

    void ingest_packet(const be13::packet_info &pi);
    void render(const std::string &outdir);
    plot_view::rgb_t port_color(uint16_t port) const;

    static std::vector<transport_type> build_display_transports();

    static const unsigned int port_colors_count;
    // string constants
    static const std::string title_version;
    static const std::vector<transport_type> display_transports;
    // ratio constants
    static const double page_margin_factor;
    static const double line_space_factor;
    static const double histogram_pad_factor_y;
    static const double address_histogram_width_divisor;
    // size constants
    static const double packet_histogram_height;
    static const double address_histogram_height;
    static const double port_histogram_height;
    // color constants
    static const plot_view::rgb_t default_color;
    static const plot_view::rgb_t color_orange;
    static const plot_view::rgb_t color_red;
    static const plot_view::rgb_t color_magenta;
    static const plot_view::rgb_t color_purple;
    static const plot_view::rgb_t color_deep_purple;
    static const plot_view::rgb_t color_blue;
    static const plot_view::rgb_t color_teal;
    static const plot_view::rgb_t color_green;
    static const plot_view::rgb_t color_yellow;
    static const plot_view::rgb_t color_light_orange;

private:

    uint64_t packet_count;
    uint64_t byte_count;
    struct timeval earliest;
    struct timeval latest;
    std::map<uint32_t, uint64_t> transport_counts;
    time_histogram packet_histogram;
    port_histogram src_port_histogram;
    port_histogram dst_port_histogram;
    packetfall pfall;
    net_map netmap;
    iptree src_tree;
    iptree dst_tree;
    std::map<uint16_t, uint16_t> port_aliases;
    std::map<uint16_t, plot_view::rgb_t> port_color_map;
};

#endif
