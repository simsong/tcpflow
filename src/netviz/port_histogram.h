#ifndef PORTHISTOGRAM_H
#define PORTHISTOGRAM_H

#include "render.h"
#include "plot.h"

class port_histogram {
public:
    typedef enum {
        SENDER = 0, RECEIVER, SND_OR_RCV
    } relationship_t;

    class config_t {
    public:
        // generic graph parent config
        plot::config_t graph;
        relationship_t relationship;
        double bar_space_factor;
        int max_bars;
    };

    port_histogram(const config_t &conf_) :
        conf(conf_), port_counts() {};

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);

    static const config_t default_config;

private:
    config_t conf;
    std::map<std::string, uint16_t> port_counts;
};

#endif
