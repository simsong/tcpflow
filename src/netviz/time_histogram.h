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

    typedef enum {
        MINUTE = 0, HOUR, DAY, WEEK, MONTH, YEAR
    } span_t;
    typedef uint64_t count_t;
    typedef uint16_t port_t;
    typedef uint32_t timescale_off_t;

    // a bucket counts packets received in a given timeframe, organized by TCP port
    class bucket {
    public:
        bucket() : counts(), sum() {}

        std::map<port_t, count_t> counts;
        count_t sum;

        void increment(port_t port, count_t delta);
    };
    class histogram_map {
    public:
        histogram_map(uint64_t time_span_) :
            buckets(), bucket_width(time_span_ / bucket_count), base_time(0),
            time_span(time_span_), sum(0), greatest_bucket_sum(0) {}

        std::map<timescale_off_t, bucket> buckets;
        uint64_t bucket_width;
        uint64_t base_time;
        uint64_t time_span;
        count_t sum;
        uint64_t greatest_bucket_sum;

        // returns true if the insertion resulted in over/underflow
        bool insert(const struct timeval &ts, const port_t port);
    };

    static const timescale_off_t bucket_count;
    static const float underflow_pad_factor;
    static const std::vector<uint64_t> span_lengths; // in microseconds
    static const bucket empty_bucket;

    void insert(const struct timeval &ts, const port_t port);
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
    static std::vector<uint64_t> build_span_lengths();

private:
    std::vector<histogram_map> histograms;
    uint32_t best_fit_index;
    struct timeval earliest_ts, latest_ts;
    count_t sum;
};

#endif
