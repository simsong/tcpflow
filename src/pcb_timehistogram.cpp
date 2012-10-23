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

#include "iface_pcb.h"
#include <cairo/cairo.h>
#include <cairo/cairo-svg.h>
#include <vector>

using std::vector;

const int NUM_HISTOGRAMS = 6;
const int NUM_BUCKETS = 3000;
const int SVG_HEIGHT = 100.0;
// to account for packets timestamped before the first we receive, start a
// little ways into the buckets
const int FIRST_BUCKET = NUM_BUCKETS / 10;
typedef enum {
    MINUTE = 0, HOUR, DAY, WEEK, MONTH, YEAR
} span_t;

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
                std::cout << (int) span << " bucket underflow " << std::endl;
                underflow_count++;
                return;
            }
            if(target_index >= NUM_BUCKETS)
            {
                std::cout << (int) span << " bucket overflow " << std::endl;
                overflow_count++;
                return;
            }

            // FIXME take out debug
            std::cout << (int) span << " inserting into bucket " << target_index << std::endl;

            bucket *target_bucket = &buckets.at(target_index);

            // FIXME
            // for now, assume everything is other until I figure out where to
            // grab port numbers from
            (*target_bucket).other++;
        }
};

// this vector must hold histograms in order from greatest time resolution to
// least
vector<histogram> histograms;

void render(const histogram selected_histogram)
{
    std::cout << "begin render!" << std::endl;
    vector<bucket> buckets = selected_histogram.buckets;
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
            bucket_sum = greatest_bucket_sum;
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
 
    surface = (cairo_surface_t *) cairo_svg_surface_create("time_histogram.svg",
            num_sig_buckets, SVG_HEIGHT);
    cr = cairo_create(surface);

    cairo_set_source_rgb(cr, 0, 0, 0);

    std::cout << "rendering from " << first_index << " to " << last_index << std::endl;
    // render pass
    index = 0;
    for(vector<bucket>::iterator bucket = buckets.begin() + first_index;
            bucket != buckets.begin() + last_index; bucket++)
    {
        // TODO differentiate types
        uint64_t bucket_sum = (*bucket).http + (*bucket).https
            + (*bucket).other;
        double bar_height = (((double) bucket_sum)
                / ((double) greatest_bucket_sum)) * SVG_HEIGHT;

        bar_height = (double) bucket_sum;

        std::cout << "bar at " << index << "," << bar_height << std::endl;
        cairo_rectangle(cr, index, bar_height, 1.0, bar_height);

        index++;
    }
 
    //cairo_surface_flush(surface);
    //cairo_surface_finish(surface);
    cairo_destroy (cr);
    cairo_surface_destroy(surface);
}

histogram select_for_render()
{
    histogram base = histograms.at(0);
    uint64_t min_dropped = base.underflow_count + base.overflow_count;
    histogram best = base;

    // find the histogram with the lowest combined underflowed and overflowed
    // packets
    // the first histogram gets uselessly compared to itself for code simplicity
    for(vector<histogram>::iterator candidate = histograms.begin();
            candidate != histograms.end(); candidate++)
    {
        uint64_t dropped = (*candidate).underflow_count +
            (*candidate).overflow_count;

        // Since we want the most resolution and the histograms vector must be
        // in descending resolution order, then if zero drops is ever
        // encountered return that immediately since the following histograms
        // with less resolution will also have zero drops but will be poorer
        // representations
        if(dropped == 0)
        {
            std::cout << "short-circuit selected " << (int) (*candidate).span << " as best histogram to render" << std::endl;
            return *candidate;
        }

        if(dropped < min_dropped)
        {
            min_dropped = dropped;
            best = *candidate;
        }
    }

    std::cout << "selected " << (int) best.span << " as best histogram to render" << std::endl;

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
            std::cout << "shutting down!" << std::endl;
            render(select_for_render());
            break;
        case pcb::none:
        default:
            return;
    }
}
