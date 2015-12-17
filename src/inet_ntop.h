#ifndef TCPFLOW_INET_NTOP_H
#define TCPFLOW_INET_NTOP_H

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src,char *dst, socklen_t size);
#endif

#if defined(__MINGW32__)
// <ws2tcpip.h> has this prototype for ws2_32 dll, but has type-conflicts with winsock2.h
WINSOCK_API_LINKAGE LPCWSTR WSAAPI inet_ntop(INT Family, PVOID pAddr, LPWSTR pStringBuf, size_t StringBufSIze);
#endif

#endif
