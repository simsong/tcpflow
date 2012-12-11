#ifndef TIMEHISTOGRAM_H
#define TIMEHISTOGRAM_H

#include "render.h"
#include "plot.h"

/**
 * interface for the timehistogram class
 */

class time_histogram {
public:
    typedef enum {
        MINUTE = 0, HOUR, DAY, WEEK, MONTH, YEAR
    } span_t;

    static const uint64_t span_lengths[];
    static const char * const unit_strings[];

    class config_t {
    public:
        // generic graph parent config
        plot::config_t graph;
        span_t span;
        double bar_space_factor;
        int bucket_count;
        // multiplied by the length of the bucket vector to find the first
        // bucket to insert into
        double first_bucket_factor;
    };
    static const config_t default_config;

    class bucket_t {
    public:
        uint64_t http;
        uint64_t https;
        uint64_t other;
    };

    time_histogram(const config_t &conf_) :
        conf(conf_), length(span_lengths[conf_.span]),
        bucket_width(length / conf.bucket_count), underflow_count(0),
        overflow_count(0), buckets(conf.bucket_count),
        base_time(0), received_data(false),
        color_http(0.05, 0.33, 0.65), color_https(0.00, 0.75, 0.20),
        color_other(1.00, 0.77, 0.00)   { }

    // render configuration
    config_t conf;
    // total number of microseconds this histogram covers
    uint64_t length;
    // number of microseconds each bucket represents
    uint64_t bucket_width;
    // number of packets that occurred before the span of this histogram
    uint64_t underflow_count;
    // number of packets that occurred after the span of this histogram
    uint64_t overflow_count;
    // packet counts
    vector<bucket_t> buckets;
    // the earliest time this histogram represents (unknown until first
    // packet received)
    uint64_t base_time;
    // have we received that first packet? (beats having to examine buckets)
    bool received_data;

    plot::rgb_t color_http;
    plot::rgb_t color_https;
    plot::rgb_t color_other;

    void ingest_packet(const packet_info &pi);

    class render_vars {
    public:
        render_vars() :
            first_index(-1), last_index(-1), greatest_bucket_sum(0),
            num_sig_buckets(0), unit_log_1000(0) {}
        void prep(const time_histogram &graph);
        int first_index;
        int last_index;
        uint64_t greatest_bucket_sum;
        int num_sig_buckets;
        uint64_t unit_log_1000;
    };
    static void time_struct_to_string(const struct tm & time_struct,
            std::stringstream &ss);
    void render(const std::string &outdir);
    void choose_subtitle(const render_vars &vars);
    plot::ticks_t build_tick_labels(const render_vars &vars);
    plot::legend_t build_legend(const render_vars &vars);
    void render_bars(cairo_t *cr, const plot::bounds_t &bounds,
            render_vars &vars);
};

class dyn_time_histogram {
public:
    dyn_time_histogram(const time_histogram::config_t &conf_);
    void ingest_packet(const packet_info &pi);
    void render(const std::string &outdir);
    time_histogram &select_best_fit();

    // render configuration to be passed to children
    time_histogram::config_t conf;
    // children
    std::vector<time_histogram> histograms;
};

#endif
