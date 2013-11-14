/**
 * port_histogram.h: 
 * Show packets received vs port
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#ifndef PORT_HISTOGRAM_H
#define PORT_HISTOGRAM_H

class port_histogram {
public:
    port_histogram() :
        port_counts(), data_bytes_ingested(0), buckets(), buckets_dirty(true) {}

    class port_count {
    public:
        port_count(uint16_t port_, uint64_t count_) :
            port(port_), count(count_) {}
        uint16_t port;
        uint64_t count;
    };
    //typedef uint16_t port_t;

    class descending_counts {
    public:
        bool operator()(const port_count &a, const port_count &b);
    };

    void increment(uint16_t port, uint64_t delta);
    const port_count &at(size_t index);
    size_t size();
    uint64_t ingest_count() const;

    typedef std::vector<port_count> port_count_vector;

    port_count_vector::const_iterator begin();
    port_count_vector::const_iterator end();
    port_count_vector::const_reverse_iterator rbegin();
    port_count_vector::const_reverse_iterator rend();

    static const size_t bucket_count;

private:
    typedef std::map<in_port_t, uint64_t> port_counts_t;
    port_counts_t port_counts;
    uint64_t data_bytes_ingested;
    std::vector<port_count> buckets;
    bool buckets_dirty;

    void refresh_buckets();
};

#endif
