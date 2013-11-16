#ifndef __WIFIPCAP_UTIL_H_
#define __WIFIPCAP_UTIL_H_

#include <ostream>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
#ifdef _WIN32
typedef unsigned long long uint64_t;
#endif

#if 0
struct MAC {
    uint64_t val;
    MAC() {}
    MAC(const uint8_t *stream);
    MAC(uint64_t val);
    MAC(const char *str);
    MAC(const MAC& o);

    bool operator==(const MAC& o) const {
	return val == o.val;
    }
    bool operator!=(const MAC& o) const {
	return val != o.val;
    }
    bool operator<(const MAC& o) const {
	return val < o.val;
    }

    enum { PRINT_FMT_COLON, PRINT_FMT_PLAIN };

    static MAC broadcast;
    static MAC null;
    static int print_fmt;
};

std::ostream& operator<<(std::ostream& out, const MAC& mac);
std::ostream& operator<<(std::ostream& out, const struct in_addr& ip);
#endif

char *va(const char *format, ...);

struct tok {
	int v;			/* value */
	const char *s;		/* string */
};

extern const char *
tok2str(register const struct tok *lp, register const char *fmt,
	register int v);

#endif
