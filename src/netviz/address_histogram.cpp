/**
 * address_histogram.cpp: 
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#include "config.h"

#ifdef HAVE_LIBCAIRO
#include "tcpflow.h"
#include "tcpip.h"

#include <math.h>
#include <iomanip>
#include <algorithm>

#include "address_histogram.h"

using namespace std;

address_histogram::address_histogram(const iptree &tree) :
    buckets(), datagrams_ingested(0)
{
    // convert iptree to suitable vector for count histogram
    iptree::histogram_t addresses;

    tree.get_histogram(addresses);

    if(addresses.size() <= bucket_count) {
        sort(addresses.begin(), addresses.end(), iptree_node_comparator());
    }
    else {
        partial_sort(addresses.begin(), addresses.begin() + bucket_count,
                addresses.end(), iptree_node_comparator());
    }
    buckets.clear();

    vector<iptree::addr_elem>::const_iterator it = addresses.begin();
    for(size_t ii = 0; ii < bucket_count && it != addresses.end(); ii++, it++) {
        buckets.push_back(*it);
    }

    datagrams_ingested = tree.sum();
}

const size_t address_histogram::bucket_count = 10;

const iptree::addr_elem &address_histogram::at(size_t index) const
{
    return buckets.at(index);
}

size_t address_histogram::size() const
{
    return buckets.size();
}

uint64_t address_histogram::ingest_count() const
{
    return datagrams_ingested;
}

address_histogram::ipt_addrs::const_iterator address_histogram::begin() const
{
    return buckets.begin();
}
address_histogram::ipt_addrs::const_iterator address_histogram::end() const
{
    return buckets.end();
}
address_histogram::ipt_addrs::const_reverse_iterator address_histogram::rbegin() const
{
    return buckets.rbegin();
}
address_histogram::ipt_addrs::const_reverse_iterator address_histogram::rend() const
{
    return buckets.rend();
}

bool address_histogram::iptree_node_comparator::operator()(const iptree::addr_elem &a,
        const iptree::addr_elem &b)
{
    if(a.count > b.count) {
        return true;
    }
    else if(a.count < b.count) {
        return false;
    }
    for(size_t ii = 0; ii < sizeof(a.addr); ii++) {
        if(a.addr[ii] > b.addr[ii]) {
            return true;
        }
        else if(a.addr[ii] < b.addr[ii]) {
            return false;
        }
    }
    return false;
}

#endif
