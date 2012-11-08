/*
 * This file is part of tcpflow by Simson Garfinkel <simsong@acm.org>.
 * Originally by Jeremy Elson <jelson@circlemud.org>.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"

#ifdef HAVE_CAIRO_CAIRO_H
#include <cairo/cairo.h>
#endif
#ifdef HAVE_CAIRO_CAIRO_PDF_H
#include <cairo/cairo-pdf.h>
#endif
#include <math.h>
#include <iomanip>
#include <vector>

#include "iface_pcb.h"

using std::vector;

#define NUM_HISTOGRAMS 6
typedef enum {
    MINUTE = 0, HOUR, DAY, WEEK, MONTH, YEAR
} span_t;

#define IPV6_HEADER_LEN 40
#define PORT_HTTP 80
#define PORT_HTTPS 443

// copied from tcpdemux.cpp - should this be in a header somewhere?
struct private_ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct private_in6_addr ip6_src;	/* source address */
	struct private_in6_addr ip6_dst;	/* destination address */
} __attribute__((__packed__));

struct graph_config_t {
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
    // used to calculate spacing of largest possible tick label
    const char *x_tick_dummy;
    const char *y_tick_dummy;
    // multiple of label dummy text length to allocate for spacing
    double tick_label_pad_factor;
    double y_tick_font_size;
    double x_tick_font_size;
    // non-dynamic padding for the right and bottom of graph
    double pad_bottom;
    double pad_right;
    // legend
    double legend_chip_edge_length;
    double legend_font_size;
};

graph_config_t default_graph_config = {
    /* filename */ "graph",
    /* title */ "graph of things",
    /* subtitle */ "x vs y",
    /* width */ 161.803,
    /* height */ 100.000,
    /* title_font_size */ 8.0,
    /* title_max_width_ratio */ 0.8,
    /* title_y_pad_factor */ 2.0,
    /* subtitle_y_pad_factor */ 0.2,
    /* subtitle_font_size_factor */ 0.4,
    /* tick_length */ 2.0,
    /* tick_width */ 0.2,
    /* x_tick_count */ 5,
    /* y_tick_count */ 5,
    /* x_tick_label_dummy */ "000.00",
    /* y_tick_label_dummy */ "000.00",
    /* tick_label_pad_factor */ 1.5,
    /* y_tick_font_size */ 3.0,
    /* x_tick_font_size */ 4.0,
    /* pad_bottom */ 8.0,
    /* pad_right */ 24.0,
    /* legend_chip_edge_length */ 4.0,
    /* legend_font_size */ 2.5
};

struct histogram_config_t {
    // generic graph parent config
    graph_config_t graph;
    double bar_space_factor;
    int bucket_count;
    // multiplied by the length of the bucket vector to find the first bucket to
    // insert into
    double first_bucket_factor;
};

histogram_config_t default_histogram_config = {
    /* graph */ default_graph_config,
    /* bar_space_factor */ 1.2,
    /* bucket_count */ 600,
    /* first_bucket_factor */ 0.1,
};

// Unit in libpcap is microsecond, so shall it be here
const uint64_t span_lengths[] = {
    /* minute */ 60L * 1000L * 1000L,
    /* hour */ 60L * 60L * 1000L * 1000L,
    /* day */ 24L * 60L * 60L * 1000L * 1000L,
    /* week */ 7L * 24L * 60L * 60L * 1000L * 1000L,
    /* month */ 30L * 24L * 60L * 60L * 1000L * 1000L,
    /* year */ 12L * 30L * 24L * 60L * 60L * 1000L * 1000L
};

const char * units_strings[] = {
    "packets vs time",
    "kilopackets vs time",
    "megapackets vs time",
    "gigapackets vs time",
    "terapackets vs time",
    "petapackets vs time",
    "exapackets vs time",
};

struct rgb_t {
    double r;
    double g;
    double b;
};

inline uint64_t extract_time(const struct pcap_pkthdr *h)
{
    return (*h).ts.tv_usec + ((*h).ts.tv_sec * 1000000L);
}

void time_format(struct tm *time, char *buf, int buflen)
{
    snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02d", 1900 + time->tm_year,
            1 + time->tm_mon, time->tm_mday, time->tm_hour, time->tm_min,
            time->tm_sec);
}

// quickly try and get the port out of the packet.  It is assumed that the
// packet is an IPv4 or 6 datagram in an ethernet frame.
// any and all errors simply result in -1 being returned
int try_and_get_port(const struct pcap_pkthdr *h, const u_char *p)
{
    // keep track of the length of the packet not yet examined
    unsigned int unused_len = h->caplen;
    if(unused_len < sizeof(struct ether_header)) {
        return -1;
    }
    unused_len -= sizeof(struct ether_header);

    struct ether_header *eth_header = (struct ether_header *) p;
    u_short *ether_type_location = &eth_header->ether_type;
    const u_char *ether_data = p + sizeof(struct ether_header);

    /* Handle basic VLAN packets */
    if(ntohs(*ether_type_location) == ETHERTYPE_VLAN) {
        // skip to real ethertype
        ether_type_location += 2;
        ether_data += 4;
        unused_len -= 4;
    }

    // only one of these is safe to use!
    const struct ip *ip_header = (struct ip *) ether_data;
    const struct private_ip6_hdr *ip6_header
        = (struct private_ip6_hdr *) ether_data;

    u_char *ip_data;

    switch(ntohs(*ether_type_location)) {
        case ETHERTYPE_IP:
            if(unused_len < sizeof(struct ip) ||
                    ip_header->ip_p != IPPROTO_TCP) {
                return -1;
            }
            unused_len -= sizeof(struct ip);
            ip_data = (u_char *) ether_data + sizeof(struct ip);
            break;
        case ETHERTYPE_IPV6:
            if(unused_len < sizeof(struct private_ip6_hdr) ||
                    ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
                return -1;
            }
            unused_len -= sizeof(struct private_ip6_hdr);
            ip_data = (u_char *) ether_data + sizeof(struct private_ip6_hdr);
            break;
        default:
            return -1;
    }

    if(unused_len < sizeof(struct tcphdr)) {
        return -1;
    }

    struct tcphdr *tcp_header = (struct tcphdr *) ip_data;

    return ntohs(tcp_header->th_dport);
}

class plotter {
    public:
#ifdef HAVE_CAIRO_CAIRO_H
        static void render(cairo_t *cr, const graph_config_t conf)
        {
            // render title

            cairo_text_extents_t title_extents;
            cairo_text_extents_t subtitle_extents;
            double font_size_title = conf.title_font_size;

            // choose subtitle based on magnitude of units
            const char *subtitle = units_strings[0];
            uint64_t unit_index =
                (uint64_t) (log(greatest_bucket_sum) / log(1000));
            if(unit_index < (sizeof(units_strings) / sizeof(char *))) {
                subtitle = units_strings[unit_index];
            }

            cairo_select_font_face(cr, "Sans",
                CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, font_size_title);
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, conf.title, &title_extents);
            // Is the title too wide?
            double title_max_width = conf.width *
                conf.title_max_width_ratio;
            if(title_extents.width > title_max_width) {
                // scale the font size accordingly
                font_size_title *= title_max_width / title_extents.width;
                cairo_text_extents(cr, conf.title, &title_extents);
            }
            // derive subtitle size and measure
            double font_size_subtitle = font_size_title *
                conf.subtitle_font_size_factor;
            cairo_set_font_size(cr, font_size_subtitle);
            cairo_text_extents(cr, subtitle, &subtitle_extents);
            double intertitle_padding = subtitle_extents.height *
                conf.subtitle_y_pad_factor;
            cairo_set_font_size(cr, font_size_title);
            double title_padded_height = title_extents.height *
                conf.title_y_pad_factor;
            double titles_padded_height = title_padded_height +
                intertitle_padding + subtitle_extents.height;
            // render title text
            cairo_move_to(cr, (conf.width - title_extents.width) / 2.0,
                    title_extents.height +
                    (title_padded_height - title_extents.height) / 2);
            cairo_show_text(cr, conf.title);
            // render subtitle text
            cairo_set_font_size(cr, font_size_subtitle);
            cairo_move_to(cr, (conf.width - subtitle_extents.width) / 2.0,
                    ((title_padded_height - title_extents.height) / 2) +
                    title_extents.height + intertitle_padding +
                    subtitle_extents.height);
            cairo_show_text(cr, subtitle);

            // render ticks

            // y ticks (packet counts)

            // scale raw bucket totals
            double y_scale_range = greatest_bucket_sum;
            if(unit_index > 0) {
                y_scale_range /= (unit_index * 1000);
            }

            cairo_text_extents_t max_tick_extents;
            cairo_set_font_size(cr, conf.y_tick_font_size);
            cairo_text_extents(cr, conf.y_tick_dummy, &max_tick_extents);
            double y_label_allotment = max_tick_extents.width *
                conf.tick_label_pad_factor;
            double left_padding = y_label_allotment + conf.tick_length;

            // translate down so the top of the window aligns with the top of
            // the graph itself
            cairo_translate(cr, 0, titles_padded_height);
            cairo_scale(cr, 1.0, 1.0 - (conf.pad_bottom /
                        conf.height));

            double y_scale_interval = y_scale_range /
                (conf.y_tick_count - 1);
            double y_tick_spacing = conf.height / conf.y_tick_count;
            for(int ii = 0; ii < conf.y_tick_count; ii++) {
                double yy = (ii * y_tick_spacing) - (conf.tick_width / 2);

                char tick_label[255];
                snprintf(tick_label, 255, "%.02f",
                        ((conf.y_tick_count - (ii + 1)) *
                         y_scale_interval));
                cairo_text_extents_t extents;
                cairo_text_extents(cr, tick_label, &extents);
                cairo_move_to(cr, (y_label_allotment - extents.width) / 2,
                        yy + (extents.height / 2));
                cairo_show_text(cr, tick_label);

                // tick mark (but not for 0)
                if(ii < conf.y_tick_count - 1) {
                    cairo_rectangle(cr, y_label_allotment, yy,
                            conf.tick_length, conf.tick_width);
                    cairo_fill(cr);
                }
            }
            cairo_identity_matrix(cr);

            // x ticks (time)

            const time_t start_unix = (base_time +
                    (bucket_width * first_index)) / (1000 * 1000);
            const time_t stop_unix = (base_time +
                    (bucket_width * last_index)) / (1000 * 1000);
            struct tm start_time = *localtime(&start_unix);
            struct tm stop_time = *localtime(&stop_unix);
            char start_str[255], stop_str[255];
            time_format(&start_time, start_str, 255);
            time_format(&stop_time, stop_str, 255);
            cairo_text_extents_t start_extents, stop_extents;

            cairo_set_font_size(cr, conf.x_tick_font_size);
            cairo_text_extents(cr, start_str, &start_extents);
            cairo_text_extents(cr, stop_str, &stop_extents);

            // translate
            cairo_translate(cr, left_padding, 0);
            cairo_scale(cr, 1.0 - ((left_padding + conf.pad_right) /
                        conf.width), 1.0);

            // draw labels
            cairo_move_to(cr, 0, conf.height -
                    (conf.pad_bottom - start_extents.height) / 2);
            cairo_show_text(cr, start_str);
            cairo_move_to(cr, conf.width - stop_extents.width,
                    conf.height -
                    (conf.pad_bottom - stop_extents.height) / 2);
            cairo_show_text(cr, stop_str);

            cairo_identity_matrix(cr);

            // render legend

            cairo_translate(cr, conf.width - conf.pad_right,
                    titles_padded_height);

            cairo_text_extents_t legend_label_extents;

            cairo_set_font_size(cr, conf.legend_font_size);

            // http
            // chip
            cairo_set_source_rgb(cr, color_http.r, color_http.g, color_http.b);
            cairo_rectangle(cr, 0, 0, conf.legend_chip_edge_length,
                    conf.legend_chip_edge_length);
            cairo_fill(cr);
            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, "HTTP", &legend_label_extents);
            cairo_move_to(cr, conf.legend_chip_edge_length * 1.5,
                    (conf.legend_chip_edge_length / 2.0) +
                    (legend_label_extents.height / 2.0));
            cairo_show_text(cr, "HTTP");

            // https
            cairo_translate(cr, 0, conf.legend_chip_edge_length);
            // chip
            cairo_set_source_rgb(cr, color_https.r, color_https.g,
                    color_https.b);
            cairo_rectangle(cr, 0, 0, conf.legend_chip_edge_length,
                    conf.legend_chip_edge_length);
            cairo_fill(cr);
            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, "HTTPS", &legend_label_extents);
            cairo_move_to(cr, conf.legend_chip_edge_length * 1.5,
                    (conf.legend_chip_edge_length / 2.0) +
                    (legend_label_extents.height / 2.0));
            cairo_show_text(cr, "HTTPS");

            // https
            cairo_translate(cr, 0, conf.legend_chip_edge_length);
            // chip
            cairo_set_source_rgb(cr, color_other.r, color_other.g,
                    color_other.b);
            cairo_rectangle(cr, 0, 0, conf.legend_chip_edge_length,
                    conf.legend_chip_edge_length);
            cairo_fill(cr);
            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, "Other", &legend_label_extents);
            cairo_move_to(cr, conf.legend_chip_edge_length * 1.5,
                    (conf.legend_chip_edge_length / 2.0) +
                    (legend_label_extents.height / 2.0));
            cairo_show_text(cr, "Other");

            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_identity_matrix(cr);
        }
#endif
    private:
        plotter()
        {
        }
};

class time_histogram {
    public:
        struct bucket_t {
            uint64_t http;
            uint64_t https;
            uint64_t other;
        };

        time_histogram(const span_t span_, histogram_config_t conf_) :
            span(span_), conf(conf_), length(span_lengths[span_]),
            bucket_width(length / conf.bucket_count), underflow_count(0),
            overflow_count(0), buckets(vector<bucket_t>(conf.bucket_count)),
            base_time(0), received_data(false), graph(plotter(conf.graph))
        {
        }

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


        void ingest_packet(const struct pcap_pkthdr *h, const u_char *p)
        {
            uint64_t time = extract_time(h);
            // if we haven't received any data yet, we need to set the base time
            if(!received_data) {
                uint64_t first_bucket = (uint64_t) ((double) conf.bucket_count *
                        conf.first_bucket_factor);
                base_time = time - (bucket_width * first_bucket);
                received_data = true;
            }

            int target_index = (time - base_time) / bucket_width;

            if(target_index < 0) {
                underflow_count++;
                return;
            }
            if(target_index >= conf.bucket_count) {
                overflow_count++;
                return;
            }

            bucket_t *target_bucket = &buckets.at(target_index);

            switch(try_and_get_port(h, p)) {
                case PORT_HTTP:
                    target_bucket->http++;
                    break;
                case PORT_HTTPS:
                    target_bucket->https++;
                    break;
                case -1:
                    // try_and_get_port() returns -1 for any error, including if
                    // there isn't a TCP segment in the packet
                    break;
                default:
                    target_bucket->other++;
            }
        }

        void render()
        {
#ifdef HAVE_CAIRO_CAIRO_H
            rgb_t color_http, color_https, color_other;
            color_http.r = 0.05;
            color_http.g = 0.33;
            color_http.b = 0.65;

            color_https.r = 0.00;
            color_https.g = 0.75;
            color_https.b = 0.20;

            color_other.r = 1.00;
            color_other.g = 0.77;
            color_other.b = 0.00;

            //vector<bucket> buckets = selected_histogram->buckets;
            // initial stat sweep:
            //   - how many significant buckets are there
            //     (between the first and last nonzero bucket)
            //   - What is the tallest bucket?
            int first_index = -1, last_index = -1, index = 0;
            int num_sig_buckets = 0;
            uint64_t greatest_bucket_sum = 0;
            for(vector<bucket_t>::iterator bucket = buckets.begin();
                    bucket != buckets.end(); bucket++) {
                uint64_t bucket_sum = (*bucket).http + (*bucket).https
                    + (*bucket).other;

                // look for first and last significant bucket
                if(bucket_sum > 0) {
                    last_index = index;
                    if(first_index < 0) {
                        first_index = index;
                    }
                }

                // look for tallest bucket (most packets)
                if(bucket_sum > greatest_bucket_sum) {
                    greatest_bucket_sum = bucket_sum;
                }

                index++;
            }
            // if there's no first significant index, then there aren't any
            // nonzero buckets.  Abort.
            if(first_index < 0) {
                return;
            }
            num_sig_buckets = last_index - first_index;

            //
            // Start rendering
            //

            cairo_t *cr;
            cairo_surface_t *surface;

            surface = (cairo_surface_t *)
                cairo_pdf_surface_create(conf.graph.filename, conf.graph.width,
                        conf.graph.height);
            cr = cairo_create(surface);

            // render title

            cairo_text_extents_t title_extents;
            cairo_text_extents_t subtitle_extents;
            double font_size_title = conf.graph.title_font_size;

            // choose subtitle based on magnitude of units
            const char *subtitle = units_strings[0];
            uint64_t unit_index =
                (uint64_t) (log(greatest_bucket_sum) / log(1000));
            if(unit_index < (sizeof(units_strings) / sizeof(char *))) {
                subtitle = units_strings[unit_index];
            }

            cairo_select_font_face(cr, "Sans",
                CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, font_size_title);
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, conf.graph.title, &title_extents);
            // Is the title too wide?
            double title_max_width = conf.graph.width *
                conf.graph.title_max_width_ratio;
            if(title_extents.width > title_max_width) {
                // scale the font size accordingly
                font_size_title *= title_max_width / title_extents.width;
                cairo_text_extents(cr, conf.graph.title, &title_extents);
            }
            // derive subtitle size and measure
            double font_size_subtitle = font_size_title *
                conf.graph.subtitle_font_size_factor;
            cairo_set_font_size(cr, font_size_subtitle);
            cairo_text_extents(cr, subtitle, &subtitle_extents);
            double intertitle_padding = subtitle_extents.height *
                conf.graph.subtitle_y_pad_factor;
            cairo_set_font_size(cr, font_size_title);
            double title_padded_height = title_extents.height *
                conf.graph.title_y_pad_factor;
            double titles_padded_height = title_padded_height +
                intertitle_padding + subtitle_extents.height;
            // render title text
            cairo_move_to(cr, (conf.graph.width - title_extents.width) / 2.0,
                    title_extents.height +
                    (title_padded_height - title_extents.height) / 2);
            cairo_show_text(cr, conf.graph.title);
            // render subtitle text
            cairo_set_font_size(cr, font_size_subtitle);
            cairo_move_to(cr, (conf.graph.width - subtitle_extents.width) / 2.0,
                    ((title_padded_height - title_extents.height) / 2) +
                    title_extents.height + intertitle_padding +
                    subtitle_extents.height);
            cairo_show_text(cr, subtitle);

            // render ticks

            // y ticks (packet counts)

            // scale raw bucket totals
            double y_scale_range = greatest_bucket_sum;
            if(unit_index > 0) {
                y_scale_range /= (unit_index * 1000);
            }

            cairo_text_extents_t max_tick_extents;
            cairo_set_font_size(cr, conf.graph.y_tick_font_size);
            cairo_text_extents(cr, conf.graph.y_tick_dummy, &max_tick_extents);
            double y_label_allotment = max_tick_extents.width *
                conf.graph.tick_label_pad_factor;
            double left_padding = y_label_allotment + conf.graph.tick_length;

            // translate down so the top of the window aligns with the top of
            // the graph itself
            cairo_translate(cr, 0, titles_padded_height);
            cairo_scale(cr, 1.0, 1.0 - (conf.graph.pad_bottom /
                        conf.graph.height));

            double y_scale_interval = y_scale_range /
                (conf.graph.y_tick_count - 1);
            double y_tick_spacing = conf.graph.height / conf.graph.y_tick_count;
            for(int ii = 0; ii < conf.graph.y_tick_count; ii++) {
                double yy = (ii * y_tick_spacing) - (conf.graph.tick_width / 2);

                char tick_label[255];
                snprintf(tick_label, 255, "%.02f",
                        ((conf.graph.y_tick_count - (ii + 1)) *
                         y_scale_interval));
                cairo_text_extents_t extents;
                cairo_text_extents(cr, tick_label, &extents);
                cairo_move_to(cr, (y_label_allotment - extents.width) / 2,
                        yy + (extents.height / 2));
                cairo_show_text(cr, tick_label);

                // tick mark (but not for 0)
                if(ii < conf.graph.y_tick_count - 1) {
                    cairo_rectangle(cr, y_label_allotment, yy,
                            conf.graph.tick_length, conf.graph.tick_width);
                    cairo_fill(cr);
                }
            }
            cairo_identity_matrix(cr);

            // x ticks (time)

            const time_t start_unix = (base_time +
                    (bucket_width * first_index)) / (1000 * 1000);
            const time_t stop_unix = (base_time +
                    (bucket_width * last_index)) / (1000 * 1000);
            struct tm start_time = *localtime(&start_unix);
            struct tm stop_time = *localtime(&stop_unix);
            char start_str[255], stop_str[255];
            time_format(&start_time, start_str, 255);
            time_format(&stop_time, stop_str, 255);
            cairo_text_extents_t start_extents, stop_extents;

            cairo_set_font_size(cr, conf.graph.x_tick_font_size);
            cairo_text_extents(cr, start_str, &start_extents);
            cairo_text_extents(cr, stop_str, &stop_extents);

            // translate
            cairo_translate(cr, left_padding, 0);
            cairo_scale(cr, 1.0 - ((left_padding + conf.graph.pad_right) /
                        conf.graph.width), 1.0);

            // draw labels
            cairo_move_to(cr, 0, conf.graph.height -
                    (conf.graph.pad_bottom - start_extents.height) / 2);
            cairo_show_text(cr, start_str);
            cairo_move_to(cr, conf.graph.width - stop_extents.width,
                    conf.graph.height -
                    (conf.graph.pad_bottom - stop_extents.height) / 2);
            cairo_show_text(cr, stop_str);

            cairo_identity_matrix(cr);

            // render legend

            cairo_translate(cr, conf.graph.width - conf.graph.pad_right,
                    titles_padded_height);

            cairo_text_extents_t legend_label_extents;

            cairo_set_font_size(cr, conf.graph.legend_font_size);

            // http
            // chip
            cairo_set_source_rgb(cr, color_http.r, color_http.g, color_http.b);
            cairo_rectangle(cr, 0, 0, conf.graph.legend_chip_edge_length,
                    conf.graph.legend_chip_edge_length);
            cairo_fill(cr);
            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, "HTTP", &legend_label_extents);
            cairo_move_to(cr, conf.graph.legend_chip_edge_length * 1.5,
                    (conf.graph.legend_chip_edge_length / 2.0) +
                    (legend_label_extents.height / 2.0));
            cairo_show_text(cr, "HTTP");

            // https
            cairo_translate(cr, 0, conf.graph.legend_chip_edge_length);
            // chip
            cairo_set_source_rgb(cr, color_https.r, color_https.g,
                    color_https.b);
            cairo_rectangle(cr, 0, 0, conf.graph.legend_chip_edge_length,
                    conf.graph.legend_chip_edge_length);
            cairo_fill(cr);
            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, "HTTPS", &legend_label_extents);
            cairo_move_to(cr, conf.graph.legend_chip_edge_length * 1.5,
                    (conf.graph.legend_chip_edge_length / 2.0) +
                    (legend_label_extents.height / 2.0));
            cairo_show_text(cr, "HTTPS");

            // https
            cairo_translate(cr, 0, conf.graph.legend_chip_edge_length);
            // chip
            cairo_set_source_rgb(cr, color_other.r, color_other.g,
                    color_other.b);
            cairo_rectangle(cr, 0, 0, conf.graph.legend_chip_edge_length,
                    conf.graph.legend_chip_edge_length);
            cairo_fill(cr);
            // label
            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_text_extents(cr, "Other", &legend_label_extents);
            cairo_move_to(cr, conf.graph.legend_chip_edge_length * 1.5,
                    (conf.graph.legend_chip_edge_length / 2.0) +
                    (legend_label_extents.height / 2.0));
            cairo_show_text(cr, "Other");

            cairo_set_source_rgb(cr, 0, 0, 0);
            cairo_identity_matrix(cr);

            // render bars

            // transform to render within the graph itself (inside title and
            // labels)
            cairo_translate(cr, left_padding,
                    titles_padded_height);
            cairo_scale(cr,
                    1.0 - ((left_padding + conf.graph.pad_right) /
                        conf.graph.width),
                    1.0 -
                    ((titles_padded_height + conf.graph.pad_bottom) /
                     conf.graph.height));

            double offset_unit = conf.graph.width / num_sig_buckets;
            double bar_width = offset_unit / conf.bar_space_factor;
            index = 0;
            for(vector<bucket_t>::iterator bucket =
                    buckets.begin() + first_index;
                    bucket != buckets.begin() + last_index; bucket++) {
                uint64_t bucket_sum = (*bucket).http + (*bucket).https
                    + (*bucket).other;
                double bar_height = (((double) bucket_sum)
                        / ((double) greatest_bucket_sum)) * conf.graph.height;

                if(bar_height > 0) {
                    double http_height = (((double) bucket->http) /
                            ((double) bucket_sum)) * bar_height;
                    double https_height = (((double) bucket->https) /
                            ((double) bucket_sum)) * bar_height;
                    double other_height = (((double) bucket->other) /
                            ((double) bucket_sum)) * bar_height;

                    double current_height = conf.graph.height - bar_height;

                    // HTTP (blue)
                    cairo_set_source_rgb(cr, color_http.r, color_http.g,
                            color_http.b);
                    cairo_rectangle(cr, index * offset_unit, current_height,
                            bar_width, http_height);
                    cairo_fill(cr);

                    current_height += http_height;

                    // HTTPS (green)
                    cairo_set_source_rgb(cr, color_https.r, color_https.g,
                            color_https.b);
                    cairo_rectangle(cr, index * offset_unit, current_height,
                            bar_width, https_height);
                    cairo_fill(cr);

                    current_height += https_height;

                    // other (yellow)
                    cairo_set_source_rgb(cr, color_other.r, color_other.g,
                            color_other.b);
                    cairo_rectangle(cr, index * offset_unit, current_height,
                            bar_width, other_height);
                    cairo_fill(cr);

                    // reset to black
                    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
                }

                index++;
            }
            // reset translation
            cairo_identity_matrix(cr);
         
            //cairo_surface_flush(surface);
            //cairo_surface_finish(surface);
            cairo_destroy (cr);
            cairo_surface_destroy(surface);
#endif
        }
};

// this vector must hold histograms in order from greatest time resolution to
// least
static vector<time_histogram> histograms;

time_histogram *select_for_render()
{
    // assume the lowest resolution histogram is best
    time_histogram *best = &histograms.back();

    // use the highest resolution histogram with no overflowed packets, or use
    // the lowest resolution histogram if all have overflow, since it should
    // almost certainly have the least since it's span is the largest
    // Histograms must be in descending order of resolution
    for(vector<time_histogram>::iterator candidate = histograms.begin();
            candidate != histograms.end(); candidate++) {
        uint64_t dropped = candidate->underflow_count +
            candidate->overflow_count;

        if(dropped == 0) {
            // this seems bad, but I don't think there's a better way.
            best = &(*candidate);
            break;
        }
    }

    return best;
}

// The plugin callback itself
void timehistogram(pcb::phase_t phase, const struct pcap_pkthdr *h,
        const u_char *p)
{
    histogram_config_t config = default_histogram_config;
    config.graph.title = "TCP Packets Received";
    config.graph.filename = "time_histogram.pdf";
    switch(phase) {
        case pcb::startup:
            // create and insert histograms in descending time resolution order
            for(int ii = 0; ii < NUM_HISTOGRAMS; ii++) {
                histograms.push_back(time_histogram((span_t)ii, config));
            }
            break;
        case pcb::scan:
            for(vector<time_histogram>::iterator histogram = histograms.begin();
                    histogram != histograms.end(); histogram++) {
                (*histogram).ingest_packet(h, p);
            }
            break;
        case pcb::shutdown:
            (*select_for_render()).render();
            break;
        case pcb::none:
        default:
            return;
    }
}
