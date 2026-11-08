#ifndef TCPFLOW_INET_NTOP_H
#define TCPFLOW_INET_NTOP_H

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#if defined(_WIN32)
#include <ws2tcpip.h>
#elif !defined(HAVE_INET_NTOP)
const char *inet_ntop(int af, const void *src,char *dst, socklen_t size);
#endif

#endif
