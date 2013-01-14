#ifndef ONE_PAGE_REPORT_H
#define ONE_PAGE_REPORT_H

#include "plot.h"
#include "time_histogram.h"
#include "count_histogram.h"
#include "address_histogram.h"
#include "port_histogram.h"
#include "packetfall.h"
#include "render.h"
#include "iptree.h"

class one_page_report {
public:
    std::string source_identifier;
    std::string filename;
    plot::bounds_t bounds;
    double header_font_size;
    double top_list_font_size;
    unsigned int histogram_show_top_n_text;

    // a single render event: content moves down a bounded cairo surface as
    // indicated by end_of_content between render method invocations
    class render_pass {
    public:
        render_pass(one_page_report &report_, cairo_t *surface_,
                const plot::bounds_t &bounds_) :
            report(report_), surface(surface_), surface_bounds(bounds_),
            end_of_content(0.0) {}

        void render_text_line(std::string text, double font_size,
                double line_space);
        void render_text(std::string text, double font_size, double x_offset,
                cairo_text_extents_t &rendered_extents);

        void render_header();
        void render_bandwidth_histogram();
        void render_address_histograms();
        void render_port_histograms();
        void render_dual_histograms_top_n(
                const vector<count_histogram::count_pair> &left_list,
                const vector<count_histogram::count_pair> &right_list,
                const plot::bounds_t &left_hist_bounds,
                const plot::bounds_t &right_hist_bounds);
        void render_map();
        void render_packetfall();

        one_page_report &report;
        cairo_t *surface;
        plot::bounds_t surface_bounds;
        double end_of_content;
    };
    friend class render_pass;

    one_page_report();

    void ingest_packet(const packet_info &pi);
    void render(const std::string &outdir);

    // string constants
    static const std::string title_version;
    static const std::vector<std::string> size_suffixes;
    // ratio constants
    static const double page_margin_factor;
    static const double line_space_factor;
    static const double histogram_pad_factor_y;
    static const double address_histogram_width_divisor;
    // size constants
    static const double bandwidth_histogram_height;
    static const double address_histogram_height;

private:

    uint64_t packet_count;
    uint64_t byte_count;
    struct timeval earliest;
    struct timeval latest;
    std::map<uint32_t, uint64_t> transport_counts;
    dyn_time_histogram bandwidth_histogram;
    address_histogram src_addr_histogram;
    address_histogram dst_addr_histogram;
    port_histogram src_port_histogram;
    port_histogram dst_port_histogram;
    packetfall pfall;
    iptree src_tree;
    iptree dst_tree;

    static std::vector<std::string> build_size_suffixes();
};

#endif
