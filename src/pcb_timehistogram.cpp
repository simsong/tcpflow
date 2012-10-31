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

#include <cairo/cairo.h>
#include <cairo/cairo-svg.h>
#include <iomanip>
#include <vector>

#include "iface_pcb.h"

using std::vector;

#define NUM_HISTOGRAMS 6
#define NUM_BUCKETS 3000
//#define NUM_BUCKETS 100
// SVG units are in pt
// The size of the SVG ends up being (bar_width + bar_space) * bar_count
// by height.  So really, these values serve to describe the aspect ratio
#define GRAPH_HEIGHT 100.0
#define GRAPH_WIDTH 161.803
#define GRAPH_BAR_SPACE_FACTOR 1.2
#define GRAPH_TITLE_FONT_BASE_SIZE 8.0
#define GRAPH_TITLE_MAX_WIDTH_FACTOR 0.8
#define GRAPH_TITLE_Y_PAD_FACTOR 2.0
#define GRAPH_SUBTITLE_Y_PAD_FACTOR 0.2
#define GRAPH_TITLE_TEXT "TCP Packets Received"
#define GRAPH_SUBTITLE_FACTOR 0.4
#define GRAPH_TICK_LENGTH 2.0
#define GRAPH_TICK_WIDTH 0.2
#define GRAPH_NUM_TICKS 5
#define GRAPH_TICK_DUMMY "000"
#define GRAPH_TICK_Y_PAD_FACTOR 1.5
#define GRAPH_TICK_Y_FONT_BASE_SIZE 4.0
#define GRAPH_BOTTOM_PAD 8.0
#define GRAPH_RIGHT_PAD 24.0
#define GRAPH_TICK_X_FONT_BASE_SIZE 4.0
// to account for packets timestamped before the first we receive, start a
// little ways into the buckets
const int FIRST_BUCKET = NUM_BUCKETS / 10;
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

struct rgb
{
    double r;
    double g;
    double b;
};

struct bucket
{
    uint64_t http;
    uint64_t https;
    uint64_t other;
};

inline uint64_t extract_time(const struct pcap_pkthdr *h)
{
    return (*h).ts.tv_usec + ((*h).ts.tv_sec * 1000000L);
}

// quickly try and get the port out of the packet.  It is assumed that the
// packet is an IPv4 or 6 datagram in an ethernet frame.
// any and all errors simply result in -1 being returned
int try_and_get_port(const struct pcap_pkthdr *h, const u_char *p)
{
    // keep track of the length of the packet not yet examined
    unsigned int unused_len = h->caplen;
    if(unused_len < sizeof(struct ether_header))
    {
        return -1;
    }
    unused_len -= sizeof(struct ether_header);

    struct ether_header *eth_header = (struct ether_header *) p;
    u_short *ether_type_location = &eth_header->ether_type;
    const u_char *ether_data = p + sizeof(struct ether_header);

    /* Handle basic VLAN packets */
    if(ntohs(*ether_type_location) == ETHERTYPE_VLAN)
    {
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

    switch(ntohs(*ether_type_location))
    {
        case ETHERTYPE_IP:
            if(unused_len < sizeof(struct ip) ||
                    ip_header->ip_p != IPPROTO_TCP)
            {
                return -1;
            }
            unused_len -= sizeof(struct ip);
            ip_data = (u_char *) ether_data + sizeof(struct ip);
            break;
        case ETHERTYPE_IPV6:
            if(unused_len < sizeof(struct private_ip6_hdr) ||
                    ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
            {
                return -1;
            }
            unused_len -= sizeof(struct private_ip6_hdr);
            ip_data = (u_char *) ether_data + sizeof(struct private_ip6_hdr);
            break;
        default:
            return -1;
    }

    if(unused_len < sizeof(struct tcphdr))
    {
        return -1;
    }

    struct tcphdr *tcp_header = (struct tcphdr *) ip_data;

    return ntohs(tcp_header->th_dport);
}

class histogram
{
    public:
        histogram(const span_t span_) :
            span(span_), length(span_lengths[span_]),
            bucket_width(length / NUM_BUCKETS), underflow_count(0),
            overflow_count(0), buckets(vector<bucket>(NUM_BUCKETS)),
            base_time(0), received_data(false)
        {
        }
        // identifier for the timescale of the histogram
        span_t span;
        // total number of microseconds this histogram covers
        uint64_t length;
        // number of microseconds each bucket represents
        uint64_t bucket_width;
        // number of packets that occurred before the span of this histogram
        uint64_t underflow_count;
        // number of packets that occurred after the span of this histogram
        uint64_t overflow_count;
        // packet counts
        vector<bucket> buckets;
        // the earliest time this histogram represents (unknown until first
        // packet received)
        uint64_t base_time;
        // have we received that first packet? (beats having to examine buckets)
        bool received_data;


        void ingest_packet(const struct pcap_pkthdr *h, const u_char *p)
        {
            uint64_t time = extract_time(h);
            // if we haven't received any data yet, we need to set the base time
            if(!received_data)
            {
                base_time = time - (bucket_width * FIRST_BUCKET);
                received_data = true;
            }

            int target_index = (time - base_time) / bucket_width;

            if(target_index < 0)
            {
                underflow_count++;
                return;
            }
            if(target_index >= NUM_BUCKETS)
            {
                overflow_count++;
                return;
            }

            bucket *target_bucket = &buckets.at(target_index);

            switch(try_and_get_port(h, p))
            {
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
};

// this vector must hold histograms in order from greatest time resolution to
// least
static vector<histogram> histograms;

void time_format(struct tm *time, char *buf, int buflen)
{
    snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02d", 1900 + time->tm_year,
            1 + time->tm_mon, time->tm_mday, time->tm_hour, time->tm_min,
            time->tm_sec);
}

void render(const histogram *selected_histogram)
{
    struct rgb color_http, color_https, color_other;
    color_http.r = 0.05;
    color_http.g = 0.33;
    color_http.b = 0.65;
    color_https.r = 0.00;
    color_https.g = 0.75;
    color_https.b = 0.20;
    color_other.r = 1.00;
    color_other.g = 0.77;
    color_other.b = 0.00;

    vector<bucket> buckets = selected_histogram->buckets;
    // initial stat sweep:
    //   - how many significant buckets are there
    //     (between the first and last nonzero bucket)
    //   - What is the tallest bucket?
    int first_index = -1, last_index = -1, index = 0;
    int num_sig_buckets = 0;
    uint64_t greatest_bucket_sum = 0;
    for(vector<bucket>::iterator bucket = buckets.begin();
            bucket != buckets.end(); bucket++)
    {
        uint64_t bucket_sum = (*bucket).http + (*bucket).https
            + (*bucket).other;

        // look for first and last significant bucket
        if(bucket_sum > 0)
        {
            last_index = index;
            if(first_index < 0)
            {
                first_index = index;
            }
        }

        // look for tallest bucket (most packets)
        if(bucket_sum > greatest_bucket_sum)
        {
            greatest_bucket_sum = bucket_sum;
        }

        index++;
    }
    // if there's no first significant index, then there aren't any nonzero
    // buckets.  Abort.
    if(first_index < 0)
    {
        return;
    }
    num_sig_buckets = last_index - first_index;

    //
    // Start rendering
    //

    cairo_t *cr;
    cairo_surface_t *surface;

    surface = (cairo_surface_t *) cairo_svg_surface_create("time_histogram.svg",
            GRAPH_WIDTH, GRAPH_HEIGHT);
    cr = cairo_create(surface);

    // render title

    cairo_text_extents_t title_extents;
    cairo_text_extents_t subtitle_extents;
    double font_size_title = GRAPH_TITLE_FONT_BASE_SIZE;

    // choose subtitle based on magnitude of units
    const char *subtitle = units_strings[0];
    uint64_t unit_index = greatest_bucket_sum / 1000;
    if(unit_index < (sizeof(units_strings) / sizeof(char *)))
    {
        subtitle = units_strings[greatest_bucket_sum / 1000];
    }

    cairo_select_font_face(cr, "Sans",
        CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_size_title);
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_text_extents(cr, GRAPH_TITLE_TEXT, &title_extents);
    // Is the title too wide?
    double title_max_width = GRAPH_WIDTH * GRAPH_TITLE_MAX_WIDTH_FACTOR;
    if(title_extents.width > title_max_width)
    {
        // scale the font size accordingly
        font_size_title *= title_max_width / title_extents.width;
        cairo_text_extents(cr, GRAPH_TITLE_TEXT, &title_extents);
    }
    // derive subtitle size and measure
    double font_size_subtitle = font_size_title * GRAPH_SUBTITLE_FACTOR;
    cairo_set_font_size(cr, font_size_subtitle);
    cairo_text_extents(cr, subtitle, &subtitle_extents);
    double intertitle_padding = subtitle_extents.height *
        GRAPH_SUBTITLE_Y_PAD_FACTOR;
    cairo_set_font_size(cr, font_size_title);
    double title_padded_height = title_extents.height *
        GRAPH_TITLE_Y_PAD_FACTOR;
    double titles_padded_height = title_padded_height + intertitle_padding +
        subtitle_extents.height;
    // render title text
    cairo_move_to(cr, (GRAPH_WIDTH - title_extents.width) / 2.0,
            title_extents.height +
            (title_padded_height - title_extents.height) / 2);
    cairo_show_text(cr, GRAPH_TITLE_TEXT);
    // render subtitle text
    cairo_set_font_size(cr, font_size_subtitle);
    cairo_move_to(cr, (GRAPH_WIDTH - subtitle_extents.width) / 2.0,
            ((title_padded_height - title_extents.height) / 2) +
            title_extents.height + intertitle_padding +
            subtitle_extents.height);
    cairo_show_text(cr, subtitle);

    // render ticks

    // y ticks (packet counts)

    // scale raw bucket totals
    double y_scale_range = greatest_bucket_sum;
    if(unit_index > 0)
    {
        y_scale_range /= unit_index;
    }

    cairo_text_extents_t max_tick_extents;
    cairo_set_font_size(cr, GRAPH_TICK_Y_FONT_BASE_SIZE);
    cairo_text_extents(cr, GRAPH_TICK_DUMMY, &max_tick_extents);
    double y_label_allotment = max_tick_extents.width * GRAPH_TICK_Y_PAD_FACTOR;
    double left_padding = y_label_allotment + GRAPH_TICK_LENGTH;

    // translate down so the top of the window aligns with the top of the graph
    // itself
    cairo_translate(cr, 0, titles_padded_height);
    cairo_scale(cr, 1.0, 1.0 - (GRAPH_BOTTOM_PAD / GRAPH_HEIGHT));

    double y_scale_interval = y_scale_range / GRAPH_NUM_TICKS;
    double y_tick_spacing = GRAPH_HEIGHT / GRAPH_NUM_TICKS;
    for(int ii = 0; ii < GRAPH_NUM_TICKS; ii++)
    {
        double yy = (ii * y_tick_spacing) - (GRAPH_TICK_WIDTH / 2);

        char tick_label[255];
        snprintf(tick_label, 255, "%d",
                (int) ((GRAPH_NUM_TICKS - (ii + 1)) * y_scale_interval));
        cairo_text_extents_t extents;
        cairo_text_extents(cr, tick_label, &extents);
        cairo_move_to(cr, (y_label_allotment - extents.width) / 2,
                yy + (extents.height / 2));
        cairo_show_text(cr, tick_label);

        // tick mark (but not for 0)
        if(ii < GRAPH_NUM_TICKS - 1)
        {
            cairo_rectangle(cr, y_label_allotment, yy, GRAPH_TICK_LENGTH,
                    GRAPH_TICK_WIDTH);
            cairo_fill(cr);
        }
    }
    cairo_identity_matrix(cr);

    // x ticks (time)

    time_t start_unix = selected_histogram->base_time /
        (1000 * 1000);
    time_t stop_unix = (selected_histogram->base_time +
            selected_histogram->length) / (1000 * 1000);
    struct tm *start_time = localtime(&start_unix);
    struct tm *stop_time = localtime(&stop_unix);
    char start_str[255], stop_str[255];
    time_format(start_time, start_str, 255);
    time_format(stop_time, stop_str, 255);
    cairo_text_extents_t start_extents, stop_extents;

    cairo_set_font_size(cr, GRAPH_TICK_X_FONT_BASE_SIZE);
    cairo_text_extents(cr, start_str, &start_extents);
    cairo_text_extents(cr, stop_str, &stop_extents);

    // translate
    cairo_translate(cr, left_padding, 0);
    cairo_scale(cr, 1.0 - ((left_padding + GRAPH_RIGHT_PAD) /
                GRAPH_WIDTH), 1.0);

    cairo_move_to(cr, 0, GRAPH_HEIGHT -
            (GRAPH_BOTTOM_PAD - start_extents.height) / 2);
    cairo_show_text(cr, start_str);
    cairo_move_to(cr, GRAPH_WIDTH - stop_extents.width, GRAPH_HEIGHT -
            (GRAPH_BOTTOM_PAD - stop_extents.height) / 2);
    cairo_show_text(cr, stop_str);

    cairo_identity_matrix(cr);

    // render bars

    // transform to render within the graph itself (inside title and labels)
    cairo_translate(cr, left_padding,
            titles_padded_height);
    cairo_scale(cr,
            1.0 - ((left_padding + GRAPH_RIGHT_PAD) / GRAPH_WIDTH),
            1.0 -
            ((titles_padded_height + GRAPH_BOTTOM_PAD) / GRAPH_HEIGHT));

    double offset_unit = GRAPH_WIDTH / num_sig_buckets;
    double bar_width = offset_unit / GRAPH_BAR_SPACE_FACTOR;
    index = 0;
    for(vector<bucket>::iterator bucket = buckets.begin() + first_index;
            bucket != buckets.begin() + last_index; bucket++)
    {
        uint64_t bucket_sum = (*bucket).http + (*bucket).https
            + (*bucket).other;
        double bar_height = (((double) bucket_sum)
                / ((double) greatest_bucket_sum)) * GRAPH_HEIGHT;

        if(bar_height > 0)
        {
            double http_height = (((double) bucket->http) /
                    ((double) bucket_sum)) * bar_height;
            double https_height = (((double) bucket->https) /
                    ((double) bucket_sum)) * bar_height;
            double other_height = (((double) bucket->other) /
                    ((double) bucket_sum)) * bar_height;

            double current_height = GRAPH_HEIGHT - bar_height;

            // other (yellow)
            cairo_set_source_rgb(cr, color_other.r, color_other.g,
                    color_other.b);
            cairo_rectangle(cr, index * offset_unit, current_height,
                    bar_width, other_height);
            cairo_fill(cr);

            current_height += other_height;

            // HTTPS (green)
            cairo_set_source_rgb(cr, color_https.r, color_https.g,
                    color_https.b);
            cairo_rectangle(cr, index * offset_unit, current_height,
                    bar_width, https_height);
            cairo_fill(cr);

            current_height += https_height;

            // HTTP (blue)
            cairo_set_source_rgb(cr, color_http.r, color_http.g,
                    color_http.b);
            cairo_rectangle(cr, index * offset_unit, current_height,
                    bar_width, http_height);
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
}

histogram *select_for_render()
{
    // assume the lowest resolution histogram is best
    histogram *best = &histograms.back();

    // use the highest resolution histogram with no overflowed packets, or use
    // the lowest resolution histogram if all have overflow, since it should
    // almost certainly have the least since it's span is the largest
    // Histograms must be in descending order of resolution
    for(vector<histogram>::iterator candidate = histograms.begin();
            candidate != histograms.end(); candidate++)
    {
        uint64_t dropped = candidate->underflow_count +
            candidate->overflow_count;

        if(dropped == 0)
        {
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
    switch(phase)
    {
        case pcb::startup:
            // create and insert histograms in descending time resolution order
            for(int ii = 0; ii < NUM_HISTOGRAMS; ii++)
            {
                histograms.push_back(histogram((span_t)ii));
            }
            break;
        case pcb::scan:
            for(vector<histogram>::iterator histogram = histograms.begin();
                    histogram != histograms.end(); histogram++)
            {
                (*histogram).ingest_packet(h, p);
            }
            break;
        case pcb::shutdown:
            render(select_for_render());
            break;
        case pcb::none:
        default:
            return;
    }
}
