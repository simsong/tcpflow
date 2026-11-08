/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "config.h"

#if !defined(HAVE_LIBPCAP) || defined(TCPFLOW_TEST_PCAP_FAKE)
#include "pcap_fake.h"

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <iostream>

#ifdef _WIN32
#include <io.h>
#define SET_BINMODE(f) _setmode(_fileno(f), _O_BINARY)
#else
#define SET_BINMODE(f) /* ignore */
#endif


/* pcap_fake's struct pcap just keeps track of the file that was opened and
 * whether or not it was byteswapped.
 */
struct pcap {
    FILE *fp;                   // input file we are reading from
    int    swapped;                     // whether magic number was swapped?
    uint32_t linktype;
    uint32_t snaplen;
    bool   error;                       // an error occured
    bool   break_loop;                  // break_loop was called
    bool   must_close;
    char   err_buf[128];
    uint8_t *pktbuf;
};

char *pcap_geterr(pcap_t *p)
{
    return p->err_buf;
}

/**
 * pcap_open_offline()
 * -- "The name "-" is a synonym for stdin" (pcap manual)
 * -- allocate the pcap_t structure
 * -- open a pcap capture file.
 */
pcap_t *pcap_open_offline(const char *fname, char *errbuf)
{
    const bool from_stdin = strcmp(fname,"-")==0;
    FILE *fp = from_stdin ? stdin : fopen(fname,"rb");
    if(!fp){
        snprintf(errbuf,PCAP_ERRBUF_SIZE,"%s:%s",fname,strerror(errno));
        return 0;
    }
    pcap_t *p = pcap_fopen_offline(fp,errbuf);
    if(p) p->must_close = !from_stdin;
    else if(!from_stdin) fclose(fp);
    return p;
}

char    *pcap_lookupdev(char *) // not implemented
{
    fprintf(stderr,"pcap_fake.cpp:pcap_lookupdev: tcpflow was compiled without LIBPCAP. Will not live capture.\n");
    return 0;
}

pcap_t  *pcap_open_live(const char *, int, int, int, char *)
{
    fprintf(stderr,"pcap_fake.cpp:pcap_open_live: tcpflow was compiled without LIBPCAP. Will not live capture.\n");
    return 0;
}

inline uint32_t swap4(uint32_t x) 
{
    return (
        ((x & 0xff000000) >> 24) |
        ((x & 0x00ff0000) >> 8)  |
        ((x & 0x0000ff00) << 8)  |
        ((x & 0x000000ff) << 24));
}

inline uint32_t swap2(uint16_t x) 
{
    return (
        ((x & 0xff00) >> 8)  |
        ((x & 0x00ff) << 8));
}

pcap_t *pcap_fopen_offline(FILE *fp, char *errbuf)
{
    SET_BINMODE(fp);
    bool swapped = false;
    struct pcap_file_header header;
    if(fread(&header,sizeof(header),1,fp)!=1){
        snprintf(errbuf,PCAP_ERRBUF_SIZE,"Cannot read pcap header");
        return 0; // cannot read header
    }
    if(header.magic==0xd4c3b2a1){                       // check for swap
        header.magic = swap4(header.magic);
        header.version_major = swap2(header.version_major);
        header.version_minor = swap2(header.version_minor);
        header.thiszone      = swap4(header.thiszone);
        header.sigfigs       = swap4(header.sigfigs);
        header.snaplen       = swap4(header.snaplen);
        header.linktype      = swap4(header.linktype);
        swapped = true;

    }
    if(header.magic != 0xa1b2c3d4){
        snprintf(errbuf,
                 PCAP_ERRBUF_SIZE,"Cannot decode pcap header 0x%x; swapped=%d",
                 header.magic,swapped);
        return 0;
    }
    if(header.version_major!=PCAP_VERSION_MAJOR || header.version_minor!=PCAP_VERSION_MINOR){
        snprintf(errbuf,
                 PCAP_ERRBUF_SIZE,"Cannot read pcap version %d.%d",
                 header.version_major,header.version_minor);
        return 0;
    }

    // Bound allocation and reject invalid snapshots before accepting records.
    if(header.snaplen == 0 || header.snaplen > 16U * 1024 * 1024){
        snprintf(errbuf,PCAP_ERRBUF_SIZE,"Invalid pcap snapshot length");
        return 0;
    }
    pcap_t *ret = (pcap_t *)calloc(1,sizeof(pcap_t));
    if(ret==0){
        snprintf(errbuf,
                 PCAP_ERRBUF_SIZE,"Cannot calloc %u bytes",(unsigned int)sizeof(pcap_t));
        return 0;
    }
    ret->pktbuf  = (uint8_t *)malloc(header.snaplen);
    if(ret->pktbuf==0) { // did we get the snaplen?
        std::cerr << "Couldn't get header snaplen";
        free(ret);                      
        return 0;
    }
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.magic = %x", header.magic);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.version_major = %d", header.version_major);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.version_minor = %d", header.version_minor);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.thiszone = %d", header.thiszone);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.sigfigs = %d", header.sigfigs);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.snaplen = %d", header.snaplen);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: header.linktype = %d",header.linktype);
    //DEBUG(100) ("pcap_fake.cpp DEBUG: ret->pktbuf = %s". ret->pktbuf);
    ret->fp      = fp;
    ret->swapped = swapped;
    ret->linktype = header.linktype;
    ret->snaplen = header.snaplen;
    return ret;
}       

/*
 * These are not implemented in pcap_fake
 */

int pcap_compile(pcap_t *p, struct bpf_program *program,
                 const char *expression, int optimize, uint32_t mask) {
    if(strlen(expression)==0){
        program->valid = true;
        return 0;       // we can compile the empty expression
    }
    return -1;                          // we cannot compile otherwise
}

int pcap_datalink(pcap_t *p) {
    return p->linktype;
}

int pcap_setfilter(pcap_t *p, struct bpf_program *prog) {
    if(prog->valid) return 0;
    return -1;
}

void pcap_freecode(struct bpf_program *program)
{
    program->valid = false;
}


int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, uint8_t *user)
{
    while(cnt !=0 && !feof(p->fp) && p->break_loop==false){
        struct pcap_pkthdr hdr;

        /* Note: struct timeval is 16 bytes on MacOS and not 8 bytes,
         * so we manually read and set up the structure
         */
        uint32_t record[4];
        size_t got = fread(record,1,sizeof(record),p->fp);
        if(got == 0 && feof(p->fp)) break;
        if(got != sizeof(record)){
            snprintf(p->err_buf,sizeof(p->err_buf),"Truncated pcap record header");
            return -1;
        }
        hdr.ts.tv_sec = record[0];
        hdr.ts.tv_usec = record[1];
        hdr.caplen = record[2];
        hdr.len = record[3];

        /* Swap the header if necessary */
        if(p->swapped){
            hdr.ts.tv_sec = swap4(hdr.ts.tv_sec);
            hdr.ts.tv_usec = swap4(hdr.ts.tv_usec);
            hdr.caplen  = swap4(hdr.caplen);
            hdr.len  = swap4(hdr.len);
        }

        /* Read the packet */
        if(hdr.caplen > p->snaplen || hdr.caplen > hdr.len){
            snprintf(p->err_buf,sizeof(p->err_buf),"Invalid pcap captured length");
            return -1;
        }
        if(fread(p->pktbuf,1,hdr.caplen,p->fp)!=hdr.caplen){
            snprintf(p->err_buf,sizeof(p->err_buf),"Truncated pcap packet data");
            return -1;
        }

        //DEBUG(100) ("pcap_fake: read tv_sec.tv_usec=%d.%06d  caplen=%d  len=%d",
        // (int)hdr.ts.tv_sec,(int)hdr.ts.tv_usec,hdr.caplen,hdr.len);

        /* Process the packet */
        (*callback)(user,&hdr,p->pktbuf);



        /* And loop */
        if(cnt>0) cnt--;                // decrease the packet count
    }
    return 0;
}

void pcap_breakloop(pcap_t *p)
{
    p->break_loop=true;
}

void    pcap_close(pcap_t *p)                     // close the file
{
    if(p->must_close) fclose(p->fp);
    free(p->pktbuf);
    free(p);
}


#endif
