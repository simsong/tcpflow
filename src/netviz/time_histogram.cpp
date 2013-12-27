/**
 * time_histogram.cpp: 
 * organize packet count histograms of various granularities while transparently
 * exposing the best-fit
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include <vector>

#include "time_histogram.h"

time_histogram::time_histogram() :
    histograms(), best_fit_index(0), earliest_ts(), latest_ts(), insert_count(0)
{
    // zero value structs courtesy stackoverflow
    // http://stackoverflow.com/questions/6462093/reinitialize-timeval-struct
    earliest_ts = (struct timeval) { 0 };
    latest_ts = (struct timeval) { 0 };

    for(std::vector<span_params>::const_iterator it = spans.begin();
            it != spans.end(); it++) {
        histograms.push_back(histogram_map(*it));
    }
}

const float time_histogram::underflow_pad_factor = 0.1;

// spans dictates the granularities of each histogram.  One histogram
// will be created per entry in this vector.  Each value must have a greater
// value of seconds than the previous
const std::vector<time_histogram::span_params> time_histogram::spans = time_histogram::build_spans();
const time_histogram::bucket time_histogram::empty_bucket; // an empty bucket
const unsigned int time_histogram::F_NON_TCP = 0x01;

void time_histogram::insert(const struct timeval &ts, const in_port_t port, const uint64_t count,
        const unsigned int flags)
{
    insert_count += count;
    if(earliest_ts.tv_sec == 0 || (ts.tv_sec < earliest_ts.tv_sec ||
                (ts.tv_sec == earliest_ts.tv_sec && ts.tv_usec < earliest_ts.tv_usec))) {
        earliest_ts = ts;
    }
    if(ts.tv_sec > latest_ts.tv_sec || (ts.tv_sec == latest_ts.tv_sec && ts.tv_usec > latest_ts.tv_usec)) {
        latest_ts = ts;
    }
    for(std::vector<histogram_map>::iterator it = histograms.begin() + best_fit_index;
            it != histograms.end(); it++) {
        bool overflowed = it->insert(ts, port, count, flags);
        // if there was an overflow and the best fit isn't already the least
        // granular histogram, downgrade granularity by one step
        if(overflowed && best_fit_index < histograms.size() - 1) {
            best_fit_index++;
        }
    }
}

// combine each bucket with (factor - 1) subsequent neighbors and increase bucket width by factor
// lots of possible optimizations ignored for simplicity's sake
void time_histogram::condense(double factor)
{
    const histogram_map &original = histograms.at(best_fit_index);
    histogram_map condensed(span_params(original.span.usec, (uint64_t) ((double) original.span.bucket_count / factor)));

    for(histogram_map::buckets_t::const_iterator it = original.buckets.begin(); it != original.buckets.end(); it++) {

        bucket &bkt = *(it->second);
        uint64_t recons_usec = it->first * original.bucket_width + original.base_time;

        struct timeval reconstructed_ts;
        reconstructed_ts.tv_usec = (time_t) (recons_usec % (1000LL * 1000LL));
        reconstructed_ts.tv_sec = (time_t) (recons_usec / (1000LL * 1000LL));

        for(bucket::counts_t::const_iterator jt = bkt.counts.begin(); jt != bkt.counts.end(); jt++) {
            condensed.insert(reconstructed_ts, jt->first, jt->second);
        }
        condensed.insert(reconstructed_ts, 0, bkt.portless_count, F_NON_TCP);
    }

    histograms.at(best_fit_index) = condensed;
}

uint64_t time_histogram::usec_per_bucket() const
{
    return histograms.at(best_fit_index).bucket_width;
}

uint64_t time_histogram::packet_count() const
{
    return histograms.at(best_fit_index).insert_count;
}

time_t time_histogram::start_date() const
{
    return earliest_ts.tv_sec;
}

time_t time_histogram::end_date() const
{
    return latest_ts.tv_sec;
}

uint64_t time_histogram::tallest_bar() const
{
    return histograms.at(best_fit_index).greatest_bucket_sum();
}

const time_histogram::bucket &time_histogram::at(uint32_t index) const {
    const histogram_map::buckets_t hgram = histograms.at(best_fit_index).buckets;
    histogram_map::buckets_t::const_iterator bkt = hgram.find(index);
    if(bkt == hgram.end()) {
        return empty_bucket;
    }
    return *(bkt->second);
}

size_t time_histogram::size() const
{
    return histograms.at(best_fit_index).buckets.size();
}

// calculate the number of buckets if this were a non-sparse data structure like a vector
size_t time_histogram::non_sparse_size() const
{
    histogram_map::buckets_t buckets = histograms.at(best_fit_index).buckets;
    histogram_map::buckets_t::const_iterator least = buckets.begin();
    if(least == buckets.end()) {
        return 0;
    }
    histogram_map::buckets_t::const_reverse_iterator most = buckets.rbegin();
    return most->first - least->first + 1;
}

time_histogram::histogram_map::buckets_t::const_iterator time_histogram::begin() const
{
    return histograms.at(best_fit_index).buckets.begin();
}
time_histogram::histogram_map::buckets_t::const_iterator time_histogram::end() const
{
    return histograms.at(best_fit_index).buckets.end();
}
time_histogram::histogram_map::buckets_t::const_reverse_iterator time_histogram::rbegin() const
{
    return histograms.at(best_fit_index).buckets.rbegin();
}
time_histogram::histogram_map::buckets_t::const_reverse_iterator time_histogram::rend() const
{
    return histograms.at(best_fit_index).buckets.rend();
}

/* This should be rewritten, because currently it is building a bunch of spans and then returning a vector which has to be copied.
 * It's very inefficient.
 */
time_histogram::span_params_vector_t time_histogram::build_spans()
{
    span_params_vector_t output;

    output.push_back(span_params(
                1000LL * 1000LL * 60LL, // minute
                600)); // 600 0.1 second buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL, // hour
                3600)); // 3,600 1 second buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL, // day
                1440)); // 1,440 1 minute buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL * 7LL, // week
                1008)); // 1,008 10 minute buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL * 30LL, // month
                720)); // 720 1 hour buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL * 30LL * 12LL, // year
                360)); // 360 1 day buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL * 3598LL, // approximate decade
                514)); // 514 1 week buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL * 30LL * 12LL * 50LL, // semicentury
                200)); // 200 3 month intervals

    return output;
}




/*
 * Insert into the time_histogram.
 *
 * This is optimized to be as fast as possible, so we compute the sums as necessary when generating the histogram.
 */

bool time_histogram::histogram_map::insert(const struct timeval &ts, const in_port_t port, const uint64_t count,
        const unsigned int flags)
{
    uint32_t target_index = scale_timeval(ts);

    if(target_index >= span.bucket_count) {
        return true;                    // overflow; will cause this histogram to be shut down
    }

    buckets_t::iterator it = buckets.find(target_index);
    if(it==buckets.end()){
        buckets[target_index] = new bucket();
    }
    buckets[target_index]->increment(port, count, flags);

    insert_count += count;

    return false;
}


