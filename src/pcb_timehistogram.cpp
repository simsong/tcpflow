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
#include <vector>

using std::vector;

const int NUM_HISTOGRAMS = 6;
const int NUM_BUCKETS = 3000;
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
                underflow_count++;
                return;
            }
            if(target_index >= NUM_BUCKETS)
            {
                overflow_count++;
                return;
            }

            // FIXME take out debug
            std::cout << (int) span << " inserting into bucket " << target_index << std::endl;

            bucket target_bucket = buckets[target_index];

            // FIXME
            // for now, assume everything is other until I figure out where to
            // grab port numbers from
            target_bucket.other++;
        }
};

vector<histogram> histograms;

// The plugin callback itself
void timehistogram(pcb::phase_t phase, const struct pcap_pkthdr *h,
        const u_char *p)
{
    switch(phase)
    {
        case pcb::startup:
            for(int ii = 0; ii < NUM_HISTOGRAMS; ii++)
            {
                histograms.push_back(histogram((span_t)ii));
            }
            break;
        case pcb::scan:
            for(int ii = 0; ii < NUM_HISTOGRAMS; ii++)
            {
                histograms[ii].ingest_packet(h, p);
            }
            break;
        case pcb::shutdown:
            break;
        case pcb::none:
        default:
            return;
    }
}
