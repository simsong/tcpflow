#ifndef PACKETFALL_H
#define PACKETFALL_H

#include "render.h"
#include "plot.h"

class packetfall {
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

    packetfall(const config_t &conf_) :
        conf(conf_) {};

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);

    static const config_t default_config;

private:
    config_t conf;
};

#endif
