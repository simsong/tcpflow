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
                default:
                    target_bucket->other++;
            }
        }
};

// this vector must hold histograms in order from greatest time resolution to
// least
vector<histogram> histograms;

void render(const histogram *selected_histogram)
{
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

    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_text_extents_t title_extents;

    double font_size_title = GRAPH_TITLE_FONT_BASE_SIZE;
    // TODO remove
    const char *title = "Packets Received (One Minute)";

    //double output_width = num_sig_buckets * offset_unit;
    //double output_height = GRAPH_HEIGHT + title_extents.height;

    surface = (cairo_surface_t *) cairo_svg_surface_create("time_histogram.svg",
            GRAPH_WIDTH, GRAPH_HEIGHT);
    cr = cairo_create(surface);

    // render title
    cairo_select_font_face (cr, "Monospace",
        CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size (cr, font_size_title);
    cairo_set_source_rgb(cr, 0, 0, 0);
    cairo_text_extents(cr, title, &title_extents);
    cairo_move_to(cr, (GRAPH_WIDTH - title_extents.width) / 2.0,
            title_extents.height);
    cairo_show_text(cr, title);

    // render bars

    // transform to render within the graph itself (inside title and labels)
    cairo_translate(cr, 0, title_extents.height);
    cairo_scale(cr, 1.0, 1.0 - (title_extents.height / GRAPH_HEIGHT));

    double offset_unit = GRAPH_WIDTH / num_sig_buckets;
    double bar_width = offset_unit / GRAPH_BAR_SPACE_FACTOR;
    index = 0;
    for(vector<bucket>::iterator bucket = buckets.begin() + first_index;
            bucket != buckets.begin() + last_index; bucket++)
    {
        // TODO differentiate types
        uint64_t bucket_sum = (*bucket).http + (*bucket).https
            + (*bucket).other;
        double bar_height = (((double) bucket_sum)
                / ((double) greatest_bucket_sum)) * GRAPH_HEIGHT;

        if(bar_height > 0)
        {
            cairo_rectangle(cr, index * offset_unit, GRAPH_HEIGHT - bar_height,
                    bar_width, bar_height);
            cairo_fill(cr);
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
