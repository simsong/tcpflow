/**
 * port_histogram.cpp: 
 * Show packets received vs port
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"

#ifdef HAVE_LIBCAIRO
#include "tcpflow.h"

#include "port_histogram.h"

#include <math.h>
#include <algorithm>

using namespace std;

const size_t port_histogram::bucket_count = 10;

bool port_histogram::descending_counts::operator()(const port_count &a,
        const port_count &b)
{
    if(a.count > b.count) {
        return true;
    }
    if(a.count < b.count) {
        return false;
    }
    return a.port < b.port;
}

void port_histogram::increment(uint16_t port, uint64_t delta)
{
    port_counts[port] += delta;
    data_bytes_ingested += delta;
    buckets_dirty = true;
}

const port_histogram::port_count &port_histogram::at(size_t index)
{
    refresh_buckets();

    return buckets.at(index);
}

size_t port_histogram::size()
{
    refresh_buckets();

    return buckets.size();
}

uint64_t port_histogram::ingest_count() const
{
    return data_bytes_ingested;
}

port_histogram::port_count_vector::const_iterator port_histogram::begin()
{
    refresh_buckets();

    return buckets.begin();
}
port_histogram::port_count_vector::const_iterator port_histogram::end()
{
    refresh_buckets();

    return buckets.end();
}
port_histogram::port_count_vector::const_reverse_iterator port_histogram::rbegin()
{
    refresh_buckets();

    return buckets.rbegin();
}
port_histogram::port_count_vector::const_reverse_iterator port_histogram::rend()
{
    refresh_buckets();

    return buckets.rend();
}

void port_histogram::refresh_buckets()
{
    if(!buckets_dirty) {
        return;
    }

    buckets.clear();

    for(port_counts_t::const_iterator it = port_counts.begin();
            it != port_counts.end(); it++) {
        buckets.push_back(port_count(it->first, it->second));
    }

    if(buckets.size() <= bucket_count) {
        sort(buckets.begin(), buckets.end(), descending_counts());
    }
    else {
        partial_sort(buckets.begin(), buckets.begin() + bucket_count,
                buckets.end(), descending_counts());
    }

    if(buckets.size() > bucket_count) {
        buckets.erase(buckets.begin() + bucket_count, buckets.end());
    }

    buckets_dirty = false;
}
#endif
