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

    for(vector<uint64_t>::const_iterator it = span_lengths.begin();
            it != span_lengths.end(); it++) {
        histograms.push_back(histogram_map(*it));
    }
}

const time_histogram::timescale_off_t time_histogram::bucket_count = 600;
const float time_histogram::underflow_pad_factor = 0.1;

// span_lengths dictates the granularities of each histogram.  One histogram
// will be created per entry in this vector.  Each value must be greater than
// the previous
const vector<uint64_t> time_histogram::span_lengths =
        time_histogram::build_span_lengths(); // in microseconds
const time_histogram::bucket time_histogram::empty_bucket;

void time_histogram::insert(const struct timeval &ts, const port_t port)
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
        bool overflowed = it->insert(ts, port);
        // if there was an overflow and the best fit isn't already the least
        // granular histogram, downgrade granularity by one step
        if(overflowed && best_fit_index < histograms.size() - 1) {
            best_fit_index++;
        }
    }
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

vector<uint64_t> time_histogram::build_span_lengths()
{
    vector<uint64_t> output;

    output.push_back(60LL * 1000LL * 1000LL); // minute
    output.push_back(60LL * 60LL * 1000LL * 1000LL); // hour
    output.push_back(24LL * 60LL * 60LL * 1000LL * 1000LL); // day
    output.push_back(7LL * 24LL * 60LL * 60LL * 1000LL * 1000LL); // week
    output.push_back(30LL * 24LL * 60LL * 60LL * 1000LL * 1000LL); // month
    output.push_back(12LL * 30LL * 24LL * 60LL * 60LL * 1000LL * 1000LL); // year
    output.push_back(12LL * 30LL * 24LL * 60LL * 60LL * 1000LL * 1000LL * 10LL); // decade
    output.push_back(12LL * 30LL * 24LL * 60LL * 60LL * 1000LL * 1000LL * 10LL * 50LL); // semicentury

    return output;
}

// time histogram map

bool time_histogram::histogram_map::insert(const struct timeval &ts, const port_t port)
{
    uint64_t raw_time = ts.tv_sec * (1000L * 1000L) + ts.tv_usec;
    if(base_time == 0) {
        base_time = raw_time - (bucket_width * (bucket_count * underflow_pad_factor));
    }

    timescale_off_t target_index = (raw_time - base_time) / bucket_width;

    /* NOTE: target_index is always >=0 since it is unsigned */
    if(/* target_index < 0 || */ target_index >= bucket_count) {
        return true;
    }

    sum++;

    bucket &target = buckets[target_index];
    target.increment(port, 1);

    if(target.sum > greatest_bucket_sum) {
        greatest_bucket_sum = target.sum;
    }

    return false;
}

// time histogram bucket

inline void time_histogram::bucket::increment(port_t port, count_t delta)
{
    counts[port] += delta;
    sum += delta;
}
