/**
 * address histogram class.
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#ifndef ADDRESS_HISTOGRAM_H
#define ADDRESS_HISTOGRAM_H

#include "iptree.h"

class address_histogram {
public:
    address_histogram(const iptree &tree);

    class iptree_node_comparator {
    public:
        bool operator()(const iptree::addr_elem &a, const iptree::addr_elem &b);
    };

    static const size_t bucket_count;

    const iptree::addr_elem &at(size_t index) const;
    size_t size() const;
    uint64_t ingest_count() const;

    typedef std::vector<iptree::addr_elem> ipt_addrs;

    ipt_addrs::const_iterator begin() const;
    ipt_addrs::const_iterator end() const;
    ipt_addrs::const_reverse_iterator rbegin() const;
    ipt_addrs::const_reverse_iterator rend() const;

private:
    ipt_addrs buckets;
    uint64_t datagrams_ingested;
};

#endif
