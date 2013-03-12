#ifndef TIME_HISTOGRAM_H
#define TIME_HISTOGRAM_H

/**
 * interface for the timehistogram class
 */

#include "tcpflow.h"

#include <map>

class time_histogram {
public:
    time_histogram();

    typedef uint64_t count_t;
    typedef uint16_t port_t;
    typedef uint32_t timescale_off_t;

    class span_params {
    public:
        span_params(count_t usec_, count_t bucket_count_) :
            usec(usec_), bucket_count(bucket_count_) {}
        count_t usec;
        count_t bucket_count;
    };

    // a bucket counts packets received in a given timeframe, organized by TCP port
    class bucket {
    public:
        bucket() : counts(), portless_count(), sum() {}

        std::map<port_t, count_t> counts;
        count_t portless_count;
        count_t sum;

        void increment(port_t port, count_t delta, unsigned int flags = 0x00);
    };
    class histogram_map {
    public:
        histogram_map(span_params span_) :
            span(span_), buckets(), bucket_width(span.usec / span.bucket_count),
            base_time(0), sum(0), greatest_bucket_sum(0) {}

        span_params span;
        std::map<timescale_off_t, bucket> buckets;
        uint64_t bucket_width;
        uint64_t base_time;
        count_t sum;
        uint64_t greatest_bucket_sum;

        // returns true if the insertion resulted in over/underflow
        bool insert(const struct timeval &ts, const port_t port, const count_t count = 1,
                const unsigned int flags = 0x00);
    };

    static const timescale_off_t bucket_count;
    static const float underflow_pad_factor;
    static const std::vector<span_params> spans; // in microseconds
    static const bucket empty_bucket;
    static const unsigned int F_NON_TCP;

    void insert(const struct timeval &ts, const port_t port, const count_t count = 1,
            const unsigned int flags = 0x00);
    void condense(int factor);
    uint64_t usec_per_bucket() const;
    count_t packet_count() const;
    time_t start_date() const;
    time_t end_date() const;
    uint64_t tallest_bar() const;
    const bucket &at(timescale_off_t index) const;
    size_t size() const;
    size_t non_sparse_size() const;
    std::map<timescale_off_t, bucket>::const_iterator begin() const;
    std::map<timescale_off_t, bucket>::const_iterator end() const;
    std::map<timescale_off_t, bucket>::const_reverse_iterator rbegin() const;
    std::map<timescale_off_t, bucket>::const_reverse_iterator rend() const;
    static std::vector<span_params> build_spans();

private:
    std::vector<histogram_map> histograms;
    uint32_t best_fit_index;
    struct timeval earliest_ts, latest_ts;
    count_t sum;
};

#endif
