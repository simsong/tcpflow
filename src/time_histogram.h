#ifndef TIMEHISTOGRAM_H
#define TIMEHISTOGRAM_H

#ifdef HAVE_LIBCAIRO
#ifdef HAVE_CAIRO_CAIRO_H
#include <cairo/cairo.h>
#endif
#ifdef HAVE_CAIRO_CAIRO_PDF_H
#include <cairo/cairo-pdf.h>
#endif
#else
#define cairo_t void			// won't be using cairo
#endif

/**
 * interface for the timehistogram class
 */

typedef enum {
    MINUTE = 0, HOUR, DAY, WEEK, MONTH, YEAR
} span_t;

/* These should probably go into the bargraph plotting class */
class rgb_t {
public:
    rgb_t(const double r_, const double g_, const double b_) :
	r(r_), g(g_), b(b_)
    {
    }
    double r;
    double g;
    double b;
};

class ticks_t {
public:
    ticks_t() :
	x_labels(), y_labels()
    {
    }
    vector<string> x_labels;
    vector<string> y_labels;
};

class legend_entry_t {
public:
    legend_entry_t(const rgb_t color_, const string label_) :
	color(color_), label(label_)
    {
    }
    rgb_t color;
    string label;
};
typedef vector<legend_entry_t> legend_t;


class time_histogram {
public:
    static const uint64_t span_lengths[];



    class graph_config_t {
    public:
	const char *filename;
	const char *title;
	const char *subtitle;
	// width and height are in pt
	double width;
	double height;
	double title_font_size;
	// Title text will be shrunk if needed such that it takes up no more than
	// this ratio of the image width
	double title_max_width_ratio;
	// multiple of title height to be allocated above graph
	double title_y_pad_factor;
	// multiple of the subtitle height that will separate the subtitle from the
	// title
	double subtitle_y_pad_factor;
	// multiple of the title font size for the subtitle font size
	double subtitle_font_size_factor;
	// size of scale ticks, in pt
	double tick_length;
	double tick_width;
	int x_tick_count;
	int y_tick_count;
	int x_tick_label_max_len;
	int y_tick_label_max_len;
	// used to calculate spacing of largest possible tick label
	const char *x_tick_dummy;
	const char *y_tick_dummy;
	// multiple of label dummy text length to allocate for spacing
	double x_tick_label_pad_factor;
	double y_tick_label_pad_factor;
	double y_tick_font_size;
	double x_tick_font_size;
	// non-dynamic padding for the right and bottom of graph
	double pad_bottom;
	double pad_right;
	// legend
	double legend_chip_edge_length;
	double legend_font_size;
    };

    class histogram_config_t {
    public:
	// generic graph parent config
	graph_config_t graph;
	double bar_space_factor;
	int bucket_count;
	// multiplied by the length of the bucket vector to find the first bucket to
	// insert into
	double first_bucket_factor;
    };
    static const histogram_config_t default_histogram_config;



    class bucket_t {
    public:
        uint64_t http;
        uint64_t https;
        uint64_t other;
    };

    

    time_histogram(const span_t span_, histogram_config_t conf_) :
        span(span_), conf(conf_), length(span_lengths[span_]),
        bucket_width(length / conf.bucket_count), underflow_count(0),
        overflow_count(0), buckets(vector<bucket_t>(conf.bucket_count)),
        base_time(0), received_data(false),
        color_http(0.05, 0.33, 0.65), color_https(0.00, 0.75, 0.20),
        color_other(1.00, 0.77, 0.00)   { }

    // identifier for the timescale of the histogram
    span_t span;
    // render configuration
    histogram_config_t conf;
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

    rgb_t color_http;
    rgb_t color_https;
    rgb_t color_other;

    void ingest_packet(const packet_info &pi);

    class render_vars {
    public:
        int first_index;
        int last_index;
        uint64_t greatest_bucket_sum;
        int num_sig_buckets;
        uint64_t unit_log_1000;
    };
    void render(const std::string &outdir);
    void render_prep(render_vars &vars);
    ticks_t build_tick_labels(render_vars &vars);
    legend_t build_legend(render_vars &vars);
    void render_bars(cairo_t *cr, render_vars &vars);
};



#endif
