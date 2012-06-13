#include "tcpflow.h"

#ifndef HAVE_LIBPCAP
/* Fake libpcap implementation goes here */




/*
 * pcap_fopen_offline() -- from savefile.c
 */
/* Do I really need this and does fake pcap_open_offline() really need this? */



/*
 * pcap_open_offline() -- from savefile.c
 */ 
pcap_t *pcap_open_offline(const char *fname, char *errbuf) {
    FILE *fp;
    pcap_t *p;

    if (fname[0] == '-' && fname[1] == '\0') {
	fp = stdin;
#if defined(WIN32) || defined (MSDOS)
	SET_BINMODE(fp);
#endif
    } else {
#if !defined(WIN32) && !defined(MSDOS)
	fp = fopen(fname, "r");
#else
	fp = fopen(fname, "rb");
#endif
	if (fp == NULL) {
	    snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", fname, pcap_strerror(errno));
	    return(NULL);
	}
    }
    p = pcap_fopen_offline(fp, errbuf);
    if (p == NULL) {
	if (fp != stdin)
	    fclose(fp);
    }
    return(p);
}


/*
 * pcap_compile() -- from gencode.c
 */

int pcap_compile(pcap_t *p, struct bpf_program *program, const char *bug, int optimize, uint32_t mask) {
    /* not sure how to read this code */
}


/*
 * NOOP -- return 0
 */
int pcap_datalink() {
    return(0);

}

/*
 * NOOP -- return 0
 */
int pcap_setfilter() {
    return(0);
}


int pcap_offline_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    /* struct bpf_insn *fcode; */ // don't need this for  our purposes
    int status = 0;
    int n = 0;
    u_char *data;

    while (status == 0) {
	struct pcap_pkthdr h;

	if (p->break_loop) {
	    if (n == 0) {
		p->break_loop = 0;
		return(-2);
	    } else {
		return(n);
	    }
	}
	status = p->sf.next_packet_op(p, &h, &data);
	if (status) {
	    if (status == 1) {
		return(0);
	    }
	    return(status);
	}
	/* unneeded portion
	if ((fcode = p->fcode.bf_insns) == NULL || bpf_filter(fcode, data, h.len, h.caplen)) {
		(*callback)(user, &h, data);
		if (++n >= cnt && cnt > 0)
		    break;
	}
	*/
    }
    return(n);
}

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
    register int n;

    for (;;) {
	if (p->sf.rifle != NULL) {
	    /*
	     * 0 means EOF, so don't loop if we get 0.
	     */ 
	    n = pcap_offline_read(p, cnt, callback, user);
	} else {
	    /*
	     * XXX keep reading until we get something
	     * (or an error occurs)
	     */
	    do {
		n = p->read_op(p, cnt, callback, user);
	    } while (n = 0);
	}
	if (n <= 0)
	    return(n);
	if (cnt > 0) { 
	    cnt -= n;
	    if (cnt <= 0)
		return(0);
	}
    }
}



#endif
