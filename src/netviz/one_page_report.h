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

    config_t conf;
    uint64_t packet_count;
    uint64_t byte_count;
    dyn_time_histogram bandwidth_histogram;
private:

    double render_header(cairo_t *cr, double end_of_content,
            const plot::bounds_t &bounds);
    double render_text_line(cairo_t *cr, std::string text, double font_size,
            double line_space, double end_of_content,
            const plot::bounds_t &parent_bounds);
    double render_bandwidth_histogram(cairo_t *cr, double end_of_content,
            const plot::bounds_t &parent_bounds);
};

#endif
