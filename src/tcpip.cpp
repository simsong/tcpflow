/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#include "tcpflow.h"

#include <iostream>
#include <sstream>

#define ZLIB_CONST
#ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#  pragma GCC diagnostic ignored "-Wundef"
#  pragma GCC diagnostic ignored "-Wcast-qual"
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

tcpip::tcpip(tcpdemux &demux_,const flow &flow_,tcp_seq isn_):
    demux(demux_),myflow(flow_),dir(unknown),isn(isn_),seen_syn(false),
    pos(0),pos_min(0),pos_max(0),
    flow_pathname(),fp(0),file_created(false),
    bytes_processed(0),last_packet_number(),out_of_order_count(0),md5(0)
{
    /* If we are outputting the transcripts, compute the filename */
    static const std::string slash("/");
    if(demux.opt_output_enabled){
	if(demux.outdir=="."){
	    flow_pathname = myflow.filename();
	} else {
	    flow_pathname = demux.outdir + slash + myflow.filename();
	}
    }
    
    if(demux.opt_md5){			// allocate a context
	md5 = (context_md5_t *)malloc(sizeof(context_md5_t));
	if(md5){			// if we had memory, init it
	    MD5Init(md5);
	}
    }
}


#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

/* This could be much more efficient */
const char *find_crlfcrlf(const char *base,size_t len)
{
    while(len>4){
	if(base[0]=='\r' && base[1]=='\n' && base[2]=='\r' && base[3]=='\n'){
	    return base;
	}
	len--;
	base++;
    }
    return 0;
}


/**
 * fake implementation of mmap and munmap if we don't have them
 */
#if !defined(HAVE_MMAP)
#define PROT_READ 0
#define MAP_FILE 0
#define MAP_SHARED 0
void *mmap(void *addr,size_t length,int prot, int flags, int fd, off_t offset)
{
    void *buf = (void *)malloc(length);
    if(!buf) return 0;
    read(fd,buf,length);			// should explore return code
    return buf;
}

void munmap(void *buf,size_t size)
{
    free(buf);
}

#endif

/**
 * Destructor is called when flow is closed.
 * It implements "after" processing.
 */
tcpip::~tcpip()
{
    static const std::string fileobject_str("fileobject");
    static const std::string filesize_str("filesize");
    static const std::string filename_str("filename");
    static const std::string tcpflow_str("tcpflow");

    if(fp) close_file();		// close the file if it is open for some reason

    std::stringstream byte_runs;

    if(demux.opt_after_header && file_created){
	/* open the file and see if it is a HTTP header */
	int fd = demux.retrying_open(flow_pathname.c_str(),O_RDONLY|O_BINARY,0);
	if(fd<0){
	    perror("open");
	}
	else {
	    char buf[4096];
	    ssize_t len;
	    len = read(fd,buf,sizeof(buf)-1);
	    if(len>0){
		buf[len] = 0;		// be sure it is null terminated
		if(strncmp(buf,"HTTP/1.1 ",9)==0){
		    /* Looks like a HTTP response. Split it.
		     * We do this with memmap  because, quite frankly, it's easier.
		     */
		    struct stat st;
		    if(fstat(fd,&st)==0){
			void *base = mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd,0);
			const char *crlf = find_crlfcrlf((const char *)base,st.st_size);
			if(crlf){
			    ssize_t head_size = crlf - (char *)base + 2;
			    demux.write_to_file(byte_runs,
					  flow_pathname+"-HTTP",
					  (const uint8_t *)base,(const uint8_t *)base,head_size);
			    if(st.st_size > head_size+4){
				size_t body_size = st.st_size - head_size - 4;
				demux.write_to_file(byte_runs,
					      flow_pathname+"-HTTPBODY",
					      (const uint8_t  *)base,(const uint8_t  *)crlf+4,body_size);
#ifdef HAVE_LIBZ
				if(demux.opt_gzip_decompress){
				    process_gzip(byte_runs,
						 flow_pathname+"-HTTPBODY-GZIP",(unsigned char *)crlf+4,body_size);
				}
#endif
			    }
			}
			munmap(base,st.st_size);
		    }
		}
	    }
	    close(fd);
	}
    }

    if(demux.xreport){
	demux.xreport->push(fileobject_str);
	if(flow_pathname.size()) demux.xreport->xmlout(filename_str,flow_pathname);
	demux.xreport->xmlout(filesize_str,pos_max);
	
	std::stringstream attrs;
	attrs << "startime='" << xml::to8601(myflow.tstart) << "' ";
	attrs << "endtime='"  << xml::to8601(myflow.tlast)  << "' ";
	attrs << "src_ipn='"  << myflow.src << "' ";
	attrs << "dst_ipn='"  << myflow.dst << "' ";
	attrs << "packets='"  << myflow.packet_count << "' ";
	attrs << "srcport='"  << myflow.sport << "' ";
	attrs << "dstport='"  << myflow.dport << "' ";
	attrs << "family='"   << (int)myflow.family << "' ";
	attrs << "out_of_order_count='" << out_of_order_count << "' ";
	
	demux.xreport->xmlout(tcpflow_str,"",attrs.str(),false);
	if(out_of_order_count==0 && md5){
	    unsigned char digest[16];
	    char hexbuf[33];
	    MD5Final(digest,md5);
	    demux.xreport->xmlout("hashdigest",
				  md5_t::makehex(hexbuf,sizeof(hexbuf),digest,sizeof(digest)),
				  "type='MD5'",false);
	    free(md5);
	}
	if(byte_runs.tellp()>0) demux.xreport->xmlout("",byte_runs.str(),"",false);
	demux.xreport->pop();
    }
}


#ifdef HAVE_LIBZ
void tcpip::process_gzip(std::stringstream &ss,
			 const std::string &fname,const unsigned char *base,size_t len)
{
    if((len>4) && (base[0]==0x1f) && (base[1]==0x8b) && (base[2]==0x08) && (base[3]==0x00)){
	size_t uncompr_size = len * 16;
	unsigned char *decompress_buf = (unsigned char *)malloc(uncompr_size);
	if(decompress_buf==0) return;	// too big?

	z_stream zs;
	memset(&zs,0,sizeof(zs));
	zs.next_in = (Bytef *)base; // note that next_in should be typedef const but is not
	zs.avail_in = len;
	zs.next_out = decompress_buf;
	zs.avail_out = uncompr_size;
		
	int r = inflateInit2(&zs,16+MAX_WBITS);
	if(r==0){
	    r = inflate(&zs,Z_SYNC_FLUSH);
	    /* Ignore the error return; process data if we got anything */
	    if(zs.total_out>0){
		demux.write_to_file(ss,fname,decompress_buf,decompress_buf,zs.total_out);
	    }
	    inflateEnd(&zs);
	}
	free(decompress_buf);
    }
}
#endif


/* Closes the file belonging to a flow, but don't take it out of the map.
 */
void tcpip::close_file()
{
    if (fp){
	struct timeval times[2];
	times[0] = myflow.tstart;
	times[1] = myflow.tstart;

	DEBUG(5) ("%s: closing file", flow_pathname.c_str());
	/* close the file and remember that it's closed */
	fflush(fp);		/* flush the file */
#if defined(HAVE_FUTIMES)
	if(futimes(fileno(fp),times)){
	    perror("futimes");
	}
#endif
#if defined(HAVE_FUTIMENS) && !defined(HAVE_FUTIMES)
	struct timespec tstimes[2];
	for(int i=0;i<2;i++){
	    tstimes[i].tv_sec = times[i].tv_sec;
	    tstimes[i].tv_nsec = times[i].tv_usec * 1000;
	}
	if(futimens(fileno(fp),tstimes)){
	    perror("futimens");
	}
#endif
	fclose(fp);
	fp = NULL;
	pos = 0;
    }
}


/*************************************************************************/

/* print the contents of this packet to the console.
 * This is nice for immediate satisfaction, but it can't handle
 * out of order packets, etc.
 */
void tcpip::print_packet(const u_char *data, uint32_t length)
{
    /* green, blue, read */
    const char *color[3] = { "\033[0;32m", "\033[0;34m", "\033[0;31m" };

    if(demux.max_bytes_per_flow>0){
	if(bytes_processed > demux.max_bytes_per_flow) return; /* too much has been printed */
	if(length > demux.max_bytes_per_flow - bytes_processed){
	    length = demux.max_bytes_per_flow - bytes_processed; /* can only output this much */
	    if(length==0) return;
	}
    }

#ifdef HAVE_PTHREAD
    if(semlock){
	if(sem_wait(semlock)){
	    fprintf(stderr,"%s: attempt to acquire semaphore failed: %s\n",progname,strerror(errno));
	    exit(1);
	}
    }
#endif

    if (use_color) fputs(dir==dir_cs ? color[1] : color[2], stdout);
    if (suppress_header == 0) printf("%s: ", flow_pathname.c_str());
    if (length != fwrite(data, 1, length, stdout)) std::cerr << "\nwrite error to fwrite?\n";

    bytes_processed += length;

    if (use_color) printf("\033[0m");

    putchar('\n');
    fflush(stdout);

#ifdef HAVE_PTHREAD
    if(semlock){
	if(sem_post(semlock)){
	    fprintf(stderr,"%s: attempt to post semaphore failed: %s\n",progname,strerror(errno));
	    exit(1);
	}
    }
#endif
}

/* store the contents of this packet to its place in its file
 * This has to handle out-of-order packets as well as writes
 * past the 4GiB boundary.
 */
void tcpip::store_packet(const u_char *data, uint32_t length, uint32_t seq)
{
    /* if we're done collecting for this flow, return now */

    /* calculate the offset into this flow.
     * This handles handle seq num* wrapping correctly
     * because tcp_seq is the right size, but it probably does not
     * handle flows larger than 4GiB.
     */
    uint32_t offset = seq - isn;

    /* Are we receiving a packet with a sequence number
     * slightly less than what we consider the ISN to be?
     * The max (though admittedly non-scaled) window of 64K should be enough.
     */
    if (offset >= 0xffff0000) {
	if(syn_seen==false){
	    if(bytes_processed==0 && pos==0){
		/* No bytes were processed; perhaps we never saw a SYN.
		 * Set the isn as if this is a seq.
		 */
		isn = seq;
		offset = seq - isn;
		DEBUG(2) ("set isn to %d having seen packet with seq (%d) on %s", isn,seq,flow_pathname.c_str());
	    } else {
		isn = seq;
		offset = seq - isn;
		DEBUG(2) ("inserted data into file");
	    }
	} else {
	    DEBUG(1) ("dropped packet with seq (%d) < isn (%d) (pos=%d delta=%d seen_syn=%d) on %s",
		      seq,isn,(int)pos,offset,seen_syn,flow_pathname.c_str());
	    return;
	}
    }

    /* reject this packet if it falls entirely outside of the range of
     * bytes we want to receive for the flow */
    if (demux.max_bytes_per_flow && (offset > demux.max_bytes_per_flow))
	return;

    /* reduce length if it goes beyond the number of bytes per flow */
    if (demux.max_bytes_per_flow){
	if(offset > demux.max_bytes_per_flow) return; // don't record beyond
	if(offset+length > demux.max_bytes_per_flow){
	    DEBUG(2) ("packet truncated by max_bytes_per_flow on %s", flow_pathname.c_str());
	    length = demux.max_bytes_per_flow - offset;
	}
    }

    if (demux.opt_output_enabled){
	/* if we don't have a file open for this flow, try to open it.
	 * return if the open fails.  Note that we don't have to explicitly
	 * save the return value because open_tcpfile() puts the file pointer
	 * into the structure for us. */
	if (fp == NULL) {
	    if (demux.open_tcpfile(this)) {
		DEBUG(1)("unable to open TCP file %s",flow_pathname.c_str());
		return;
	    }
	}
	
	/* if we're not at the correct point in the file, seek there */
	if (offset != pos) {
	    fseek(fp, offset, SEEK_SET);
	    out_of_order_count++;
	}
	
	/* write the data into the file */
	DEBUG(25) ("%s: writing %ld bytes @%ld", flow_pathname.c_str(),
		   (long) length, (long) offset);
	
	if (fwrite(data, length, 1, fp) != 1) {
	    if (debug_level >= 1) {
		DEBUG(1) ("write to %s failed: ", flow_pathname.c_str());
		perror("");
	    }
	}
	if (out_of_order_count==0 && md5){
	    MD5Update(md5,data,length);
	}
	fflush(fp);
    }

    /* update instance variables */
    if(bytes_processed==0 || pos<pos_min) pos_min = pos;

    bytes_processed += length;		// more bytes have been processed
    pos = offset + length;		// new pos
    if (pos>pos_max) pos_max = pos;	// new max
}
