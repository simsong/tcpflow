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
    std::vector<iptree::addr_elem>::const_iterator begin() const;
    std::vector<iptree::addr_elem>::const_iterator end() const;
    std::vector<iptree::addr_elem>::const_reverse_iterator rbegin() const;
    std::vector<iptree::addr_elem>::const_reverse_iterator rend() const;

private:
    std::vector<iptree::addr_elem> buckets;
    uint64_t datagrams_ingested;
};

#endif
