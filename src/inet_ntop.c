/**
 * private implementaiton if inet_ntop for systems that don't have it.
 * Functionally, correct, this version doesn't do condensing of IPv6 addresses,
 * and is kind of slow.
 * 
 * This is included if the OS does not have inet_ntop.
 *
 * PUBLIC DOMAIN.
 * Simson L. Garfinkel, Jan 20, 2013
 */

static const char *inet_ntop4(const struct in_addr *addr, char *buf, socklen_t buflen)
{
    const uint8_t *a = (uint8_t *)addr;
    snprintf(buf,buflen,"%03d.%03d.%03d.%03d", a[0], a[1], a[2], a[3]);
    return buf;
}

static const char *inet_ntop6(const struct private_in6_addr *addr, char *buf, socklen_t buflen)
{
    const char *obuf=buf;
    const uint8_t *a = (uint8_t *)addr;
    for(size_t i=0;i<16;i++){
        if(buflen<2) return 0;        /* can't convert */
        snprintf(buf,buflen,"%02x",a[i]);
        buf+=2;
        buflen-=2;
        if(i>0 && i<15 && i%2==1){
            if(buflen<1) return 0;
            buf[0] = ':';
            buf++;
            buflen--;
        }
    }
    if(buflen<1) return 0;
    buf[0] = 0;
    return obuf;
}

const char *
inet_ntop(int af, const void *addr, char *buf, socklen_t len)
{
    switch(af){
    case AF_INET:
        return inet_ntop4((const struct in_addr *)addr, buf, len);
    case AF_INET6:
        return inet_ntop6((const struct private_in6_addr *)addr, buf, len);
    }
    return NULL;
}
