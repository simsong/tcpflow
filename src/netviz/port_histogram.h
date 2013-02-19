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
    typedef uint16_t port_t;

    class descending_counts {
    public:
        bool operator()(const port_count &a, const port_count &b);
    };

    void increment(uint16_t port, uint64_t delta);
    const port_count &at(size_t index);
    size_t size();
    uint64_t ingest_count() const;
    std::vector<port_count>::const_iterator begin();
    std::vector<port_count>::const_iterator end();
    std::vector<port_count>::const_reverse_iterator rbegin();
    std::vector<port_count>::const_reverse_iterator rend();

    static const size_t bucket_count;

private:
    std::map<uint16_t, uint64_t> port_counts;
    uint64_t data_bytes_ingested;
    std::vector<port_count> buckets;
    bool buckets_dirty;

    void refresh_buckets();
};

#endif
