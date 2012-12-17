#ifndef ONE_PAGE_REPORT_H
#define ONE_PAGE_REPORT_H

#include "plot.h"
#include "time_histogram.h"

class one_page_report {
public:

    class config_t {
    public:
        const char *filename;
        plot::bounds_t bounds;
        double header_font_size;
    };

    one_page_report(const config_t &conf_);

    void ingest_packet(const packet_info &pi);
    void render(const std::string &outdir);

    static const config_t default_config;

    // string constants
    static const std::string title_version;
    static const std::vector<std::string> size_suffixes;
    // ratio constants
    static const double page_margin_factor;
    static const double line_space_factor;

private:

    config_t conf;
    uint64_t packet_count;
    uint64_t byte_count;
    struct timeval earliest;
    struct timeval latest;
    std::map<uint32_t, uint64_t> transport_counts;
    dyn_time_histogram bandwidth_histogram;

    static std::vector<std::string> build_size_suffixes();

    double render_header(cairo_t *cr, double end_of_content,
            const plot::bounds_t &bounds);
    double render_text_line(cairo_t *cr, std::string text, double font_size,
            double line_space, double end_of_content,
            const plot::bounds_t &parent_bounds);
    double render_bandwidth_histogram(cairo_t *cr, double end_of_content,
            const plot::bounds_t &parent_bounds);
};

#endif
