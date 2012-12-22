/**
 * net_tcp.h: 
 * common functions and definitions related to the Transmission Control Protocol
 *
 * This source file is public domain, as it is not based on the original tcpflow.
 *
 * Author: Michael Shick <mike@shick.in>
 *
 */

#ifndef NET_TCP_H
#define NET_TCP_H

class packet_info;

class net_tcp {
public:
    static int get_port(const packet_info &pi);
private:
    net_tcp() {}
};

#endif
