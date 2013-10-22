/**
 * Interface for the timehistogram class
 * Currently this is a histogram that's specialized to create a stacked bar graph
 * with up to 2^16 different values on each bar.
 *
 * Times are stored as 64-bit microseconds since January 1, 1970
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 * 
 * History:
 * 2013-01-01 - Initial version by Mike Shick
 */


#ifndef TIME_HISTOGRAM_H
#define TIME_HISTOGRAM_H

#include "tcpflow.h"
#include <map>

class time_histogram {
public:
    time_histogram();

    //typedef uint64_t count_t;           // counts in a slot
    //typedef uint16_t port_t;            // port number
    //typedef int32_t timescale_off_t;   // ordinal offset within the histogram

    // parameter for...?
    class span_params {
    public:
        span_params(uint64_t usec_, uint64_t bucket_count_) :
            usec(usec_), bucket_count(bucket_count_) {}
        uint64_t usec;
        uint64_t bucket_count;
    };
    typedef std::vector<span_params> span_params_vector_t;

    // a bucket counts packets received in a given timeframe, organized by TCP port
    class bucket {
    public:
        typedef std::map<in_port_t, uint64_t> counts_t;
        bucket() : counts(), portless_count(){};
        uint64_t sum() const {
            /* this could be done with std::accumulate */
            uint64_t count = 0;
            for(counts_t::const_iterator it=counts.begin();it!=counts.end();it++){
                count += it->second;
            }
            count += portless_count;
            return count;
        };
        counts_t counts;
        uint64_t portless_count;
        void increment(in_port_t port, uint64_t delta, unsigned int flags = 0x00) {
            if(flags & F_NON_TCP) {
                portless_count += delta;
            }
            else {
                counts[port] += delta;
            }
        }
    };

    class histogram_map {
    public:
        typedef std::map<uint32_t, bucket *> buckets_t;
        buckets_t buckets;
        histogram_map(span_params span_) :
            buckets(), span(span_), bucket_width(span.usec / span.bucket_count),
            base_time(0), insert_count(0){}

        span_params span;
        uint64_t bucket_width;          // in microseconds
        uint64_t base_time;             // microseconds since Jan 1, 1970; set on first call to scale_timeval
        uint64_t insert_count;                   // of entire histogram

        uint64_t greatest_bucket_sum() const {
            uint64_t greatest = 0;
            for(buckets_t::const_iterator it = buckets.begin();it!=buckets.end();it++){
                if(it->second->sum() > greatest) greatest = it->second->sum();
            }
            return greatest;
        }

        /** convert timeval to a scaled time.  */
        uint32_t scale_timeval(const struct timeval &ts) {
            uint64_t raw_time = ts.tv_sec * (1000LL * 1000LL) + ts.tv_usec;
            if(base_time == 0) {
                base_time = raw_time - (bucket_width * ((uint64_t)(span.bucket_count * underflow_pad_factor)));
                // snap base time to nearest bucket_width to simplify bar labelling later
                uint64_t unit = span.usec / span.bucket_count;
                base_time = (base_time / unit) * unit;
            }
            if (raw_time < base_time) return -1; // underflow
            return (raw_time - base_time) / bucket_width;
        }

        // returns true if the insertion resulted in over/underflow
        bool insert(const struct timeval &ts, const in_port_t port, const uint64_t count = 1,
                const unsigned int flags = 0x00);
    };

    void insert(const struct timeval &ts, const in_port_t port, const uint64_t count = 1,
            const unsigned int flags = 0x00);
    void condense(double factor);
    uint64_t usec_per_bucket() const;
    uint64_t packet_count() const;
    time_t start_date() const;
    time_t end_date() const;
    uint64_t tallest_bar() const;
    const bucket &at(uint32_t index) const;
    size_t size() const;
    size_t non_sparse_size() const;

    /* iterators for the buckets */
    histogram_map::buckets_t::const_iterator begin() const;
    histogram_map::buckets_t::const_iterator end() const;
    histogram_map::buckets_t::const_reverse_iterator rbegin() const;
    histogram_map::buckets_t::const_reverse_iterator rend() const;
    static span_params_vector_t build_spans();

private:
    std::vector<histogram_map> histograms;
    uint32_t best_fit_index;
    struct timeval earliest_ts, latest_ts;
    uint64_t insert_count;

    /** configuration:
     */
    static const uint32_t bucket_count;
    static const float underflow_pad_factor;
    static const std::vector<span_params> spans; // in microseconds
    static const bucket empty_bucket;
public:
    static const unsigned int F_NON_TCP;
};

#endif
