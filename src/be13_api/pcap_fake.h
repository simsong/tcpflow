/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * pcap_fake.h
 * A fake libpcap implementation that can only read files without a filter.
 */

#include <sys/cdefs.h>
#include <stdint.h>
#include <sys/time.h>
#include <stdio.h>

__BEGIN_DECLS

/*
 * Version number of the current version of the pcap file format.
 *
 * NOTE: this is *NOT* the version number of the libpcap library.
 * To fetch the version information for the version of libpcap
 * you're using, use pcap_lib_version().
 */
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_ERRBUF_SIZE 256
    
    
struct pcap_file_header {
    uint32_t magic;                     // d4 c3 b2 a1
    uint16_t version_major;             // 02 00
    uint16_t version_minor;             // 04 00
    int32_t  thiszone;                  /* gmt to local correction - 00 00 00 00*/
    uint32_t sigfigs;   /* accuracy of timestamps */
    uint32_t snaplen;   /* max length saved portion of each pkt */
    uint32_t linktype;  /* data link type (LINKTYPE_*) */
} __attribute__((packed));
struct pcap_pkthdr {
    struct timeval ts;  /* time stamp; native */
    uint32_t caplen;    /* length of portion present */
    uint32_t len;       /* length this packet (off wire) */
}__attribute__((packed));

/* What we need after opening the file to process each next packet */
typedef struct pcap pcap_t;

/*
 * Taken from pcap-int.h
 */
//typedef int (*setfilter_op_t)(pcap_t *, struct bpf_program *);
typedef void (*pcap_handler)(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);

struct bpf_program {
    int valid;                          // set true if filter is valid
};

char    *pcap_lookupdev(char *);        // not implemented
pcap_t  *pcap_open_live(const char *, int, int, int, char *); // not implemented
pcap_t  *pcap_open_offline(const char *, char *); // open the file; set f
pcap_t  *pcap_fopen_offline(FILE *fp,char *errbuf);
void    pcap_close(pcap_t *);                     // close the file
int     pcap_loop(pcap_t *, int, pcap_handler, uint8_t *); // read the file and call loopback on each packet
int     pcap_datalink(pcap_t *);                          // noop
int     pcap_setfilter(pcap_t *, struct bpf_program *);   // noop
int     pcap_compile(pcap_t *, struct bpf_program *, const char *, int, uint32_t); // generate error if filter provided
char    *pcap_geterr(pcap_t *);
/*
 * These are the types that are the same on all platforms, and that
 * have been defined by <net/bpf.h> for ages.
 */
#define DLT_NULL        0       /* BSD loopback encapsulation */
#define DLT_EN10MB      1       /* Ethernet (10Mb) */
#define DLT_EN3MB       2       /* Experimental Ethernet (3Mb) */
#define DLT_AX25        3       /* Amateur Radio AX.25 */
#define DLT_PRONET      4       /* Proteon ProNET Token Ring */
#define DLT_CHAOS       5       /* Chaos */
#define DLT_IEEE802     6       /* 802.5 Token Ring */
#define DLT_ARCNET      7       /* ARCNET, with BSD-style header */
#define DLT_SLIP        8       /* Serial Line IP */
#define DLT_PPP         9       /* Point-to-point Protocol */
#define DLT_FDDI        10      /* FDDI */
#define DLT_RAW         101     /* just packets */


__END_DECLS


