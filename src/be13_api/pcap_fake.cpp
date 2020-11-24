/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "config.h"

#ifndef HAVE_LIBPCAP
#include "pcap_fake.h"

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <iostream>

#ifdef WIN32
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
    bool   error;                       // an error occured
    bool   break_loop;                  // break_loop was called
    bool   must_close;
    char   err_buf[128];
    uint8_t *pktbuf;
};

char *pcap_geterr(pcap_t *p)
{
    snprintf(p->err_buf,sizeof(p->err_buf),"not implemented in pcap_fake");
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
    FILE *fp = strcmp(fname,"-")==0 ? stdin : fopen(fname,"rb");
    if(!fp){
        snprintf(errbuf,PCAP_ERRBUF_SIZE,"%s:%s",fname,strerror(errno));
        return 0;
    }
    pcap_t *p = pcap_fopen_offline(fp,errbuf);
    if(p && p->fp!=stdin) p->must_close = true;
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


int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, uint8_t *user)
{
    while(cnt !=0 && !feof(p->fp) && p->break_loop==false){
        uint32_t tv_sec;
        uint32_t tv_usec;

        struct pcap_pkthdr hdr;

        /* Note: struct timeval is 16 bytes on MacOS and not 8 bytes,
         * so we manually read and set up the structure
         */
        if(fread(&tv_sec,sizeof(uint32_t),1,p->fp)!=1) break;
        if(fread(&tv_usec,sizeof(uint32_t),1,p->fp)!=1) break;
        hdr.ts.tv_sec  = tv_sec;
        hdr.ts.tv_usec = tv_usec;
        
        if(fread(&hdr.caplen,sizeof(uint32_t),1,p->fp)!=1) break;
        if(fread(&hdr.len,sizeof(uint32_t),1,p->fp)!=1) break;

        /* Swap the header if necessary */
        if(p->swapped){
            hdr.ts.tv_sec = swap4(hdr.ts.tv_sec);
            hdr.ts.tv_usec = swap4(hdr.ts.tv_usec);
            hdr.caplen  = swap4(hdr.caplen);
            hdr.len  = swap4(hdr.len);
        }

        /* Read the packet */
        if(fread(p->pktbuf,hdr.caplen,1,p->fp)!=1) break; // no more to read

        //DEBUG(100) ("pcap_fake: read tv_sec.tv_usec=%d.%06d  caplen=%d  len=%d",
        // (int)hdr.ts.tv_sec,(int)hdr.ts.tv_usec,hdr.caplen,hdr.len);

        /* Process the packet */
        (*callback)(user,&hdr,p->pktbuf);



        /* And loop */
        if(cnt>0) cnt--;                // decrease the packet count
    }
    return 0;
}

void pcap_break_loop(pcap_t *p)
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
