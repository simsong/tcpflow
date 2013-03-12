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

using namespace std;

time_histogram::time_histogram() :
    histograms(), best_fit_index(0), earliest_ts(), latest_ts(), sum(0)
{
    // zero value structs courtesy stackoverflow
    // http://stackoverflow.com/questions/6462093/reinitialize-timeval-struct
    earliest_ts = (struct timeval) { 0 };
    latest_ts = (struct timeval) { 0 };

    for(vector<span_params>::const_iterator it = spans.begin();
            it != spans.end(); it++) {
        histograms.push_back(histogram_map(*it));
    }
}

const float time_histogram::underflow_pad_factor = 0.1;

// spans dictates the granularities of each histogram.  One histogram
// will be created per entry in this vector.  Each value must have a greater
// value of seconds than the previous
const vector<time_histogram::span_params> time_histogram::spans = time_histogram::build_spans();
const time_histogram::bucket time_histogram::empty_bucket;
const unsigned int time_histogram::F_NON_TCP = 0x01;

void time_histogram::insert(const struct timeval &ts, const port_t port, const count_t count,
        const unsigned int flags)
{
    sum++;
    if(earliest_ts.tv_sec == 0 || (ts.tv_sec < earliest_ts.tv_sec ||
                (ts.tv_sec == earliest_ts.tv_sec && ts.tv_usec < earliest_ts.tv_usec))) {
        earliest_ts = ts;
    }
    if(ts.tv_sec > latest_ts.tv_sec || (ts.tv_sec == latest_ts.tv_sec && ts.tv_usec > latest_ts.tv_usec)) {
        latest_ts = ts;
    }
    for(vector<histogram_map>::iterator it = histograms.begin() + best_fit_index;
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
void time_histogram::condense(int factor)
{
    const histogram_map &original = histograms.at(best_fit_index);
    histogram_map condensed(span_params(original.span.usec, original.span.bucket_count / factor));

    for(map<timescale_off_t, bucket>::const_iterator it = original.buckets.begin();
            it != original.buckets.end(); it++) {

        const bucket &bkt = it->second;
        uint64_t recons_usec = it->first * original.bucket_width + original.base_time;
        //uint64_t recons_usec = it->first + original.base_time;
        struct timeval reconstructed_ts = { (time_t) (recons_usec % 1000 * 1000),
            (time_t) (recons_usec / 1000 * 1000) };

        for(map<port_t, count_t>::const_iterator jt = bkt.counts.begin();
                jt != bkt.counts.end(); jt++) {
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

time_histogram::count_t time_histogram::packet_count() const
{
    return histograms.at(best_fit_index).sum;
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
    return histograms.at(best_fit_index).greatest_bucket_sum;
}

const time_histogram::bucket &time_histogram::at(timescale_off_t index) const {
    const map<timescale_off_t, bucket> &hgram = histograms.at(best_fit_index).buckets;
    map<timescale_off_t, bucket>::const_iterator bkt = hgram.find(index);
    if(bkt == hgram.end()) {
        return empty_bucket;
    }
    return bkt->second;
}

size_t time_histogram::size() const
{
    return histograms.at(best_fit_index).buckets.size();
}

// calculate the number of buckets if this were a non-sparse data structure like a vector
size_t time_histogram::non_sparse_size() const
{
    map<timescale_off_t, bucket> buckets = histograms.at(best_fit_index).buckets;

    map<timescale_off_t, bucket>::const_iterator least = buckets.begin();
    map<timescale_off_t, bucket>::const_reverse_iterator most = buckets.rbegin();
    if(least == buckets.end()) {
        return 0;
    }
    return most->first - least->first + 1;
}

map<time_histogram::timescale_off_t, time_histogram::bucket>::const_iterator
        time_histogram::begin() const
{
    return histograms.at(best_fit_index).buckets.begin();
}
map<time_histogram::timescale_off_t, time_histogram::bucket>::const_iterator
        time_histogram::end() const
{
    return histograms.at(best_fit_index).buckets.end();
}
map<time_histogram::timescale_off_t, time_histogram::bucket>::const_reverse_iterator
        time_histogram::rbegin() const
{
    return histograms.at(best_fit_index).buckets.rbegin();
}
map<time_histogram::timescale_off_t, time_histogram::bucket>::const_reverse_iterator
        time_histogram::rend() const
{
    return histograms.at(best_fit_index).buckets.rend();
}

vector<time_histogram::span_params> time_histogram::build_spans()
{
    vector<span_params> output;

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
                1000LL * 1000LL * 60LL * 60LL * 24LL * 30LL * 12LL * 10LL, // decade
                514)); // 514 7.004 day (~week) buckets
    output.push_back(span_params(
                1000LL * 1000LL * 60LL * 60LL * 24LL * 30LL * 12LL * 50LL, // semicentury
                200)); // 200 3 month intervals

    return output;
}

// time histogram map

bool time_histogram::histogram_map::insert(const struct timeval &ts, const port_t port, const count_t count,
        const unsigned int flags)
{
    uint64_t raw_time = ts.tv_sec * (1000L * 1000L) + ts.tv_usec;
    if(base_time == 0) {
        base_time = raw_time - (bucket_width * (span.bucket_count * underflow_pad_factor));
    }

    timescale_off_t target_index = (raw_time - base_time) / bucket_width;

    if(target_index >= span.bucket_count) {
        return true;
    }

    sum += count;

    bucket &target = buckets[target_index];
    target.increment(port, count, flags);

    if(target.sum > greatest_bucket_sum) {
        greatest_bucket_sum = target.sum;
    }

    return false;
}

// time histogram bucket

inline void time_histogram::bucket::increment(port_t port, count_t delta, unsigned int flags)
{
    if(flags & F_NON_TCP) {
        portless_count += delta;
    }
    else {
        counts[port] += delta;
    }
    sum += delta;
}
