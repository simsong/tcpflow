/*
 * pcap_fake.h
 * A fake libpcap implementation that can only read files without a filter.
 */

#ifdef __cplusplus
extern "C" {
#endif
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
    
    
    typedef struct pcap pcap_t;
    struct pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;	/* gmt to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length saved portion of each pkt */
	uint32_t linktype;	/* data link type (LINKTYPE_*) */
    };
    struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
    };

    /*
     * Taken from pcap-int.h -- For reading saved files
     */    
    struct pcap_sf {
	FILE *rfile;
	int32_t (*next_packet_op)(pcap_t *, struct pcap_pkthdr *, u_char **);
	int32_t swapped;
	size_t hdrsize;
	swapped_type_t lengths_swapped;
	int32_t version_major;
	int32_t version_minor;
	uint32_t ifcount;    /* number of interfaces seen in this capture */
	uint32_t tsresol;    /* time stamp resolution */
	uint32_t tsscale;    /* scaling factor for resolution -> microseconds */
	uint64_t tsoffset;   /* time stamp offset */
    };

    /*
     * Taken from pcap-int.h
     */
    typedef int (*read_op_t)(pcap_t *, int cnt, pcap_handler, u_char *);
    read_op_t read_op;

    /*
     * Taken from pcap-int.h
     */
    typedef int (*setfilter_op_t)(pcap_t *, struct bpf_program *);
    setfilter_op_t setfilter_op;
    
    typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

    struct bpf_program {
	void *error;			// don't use program in pcap_fake
    };

    struct pcap {
	FILE *f;			// input file we are reading from
    };

    char	*pcap_lookupdev(char *); // generate an error
    pcap_t	*pcap_open_live(const char *, int, int, int, char *); // generate an error
    pcap_t	*pcap_open_offline(const char *, char *); // open the file; set f
    void	pcap_close(pcap_t *);			  // close the file
    int	pcap_loop(pcap_t *, int, pcap_handler, u_char *); // read the file and call loopback on each packet
    int	pcap_datalink(pcap_t *);			  // noop
    int	pcap_setfilter(pcap_t *, struct bpf_program *);	  // noop
    int	pcap_compile(pcap_t *, struct bpf_program *, const char *, int, uint32_t); // generate error if filter provided
    int pcap_offline_read(pcap_t *, int, pcap_handler, u_char *);
#ifdef __cplusplus
    };
#endif

#endif
