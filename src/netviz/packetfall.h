#ifndef PACKETFALL_H
#define PACKETFALL_H

#include "plot.h"

class packetfall {
public:
    typedef enum {
        SENDER = 0, RECEIVER, SND_OR_RCV
    } relationship_t;

    packetfall() :
        parent() {};

    void ingest_packet(const packet_info &pi);
    void render(cairo_t *cr, const plot::bounds_t &bounds);

    plot parent;
};

#endif
