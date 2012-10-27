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



/* Create a new tcp object.
 * Notice that nsn is not set because the file isn't open...
 */
tcpip::tcpip(tcpdemux &demux_,const flow &flow_,tcp_seq isn_):
    demux(demux_),myflow(flow_),dir(unknown),isn(isn_),nsn(0),seen_syn(false),
    pos(0),
    flow_pathname(),fd(-1),file_created(false),
    bytes_processed(0),omitted_bytes(),last_packet_number(),out_of_order_count(0),violations(0),md5(0)
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

    if(fd>=0) close_file();		// close the file if it is open for some reason

    std::stringstream byte_runs;

    if(demux.opt_after_header && file_created){
	/* open the file and see if it is a HTTP header */
	int fd2 = demux.retrying_open(flow_pathname.c_str(),O_RDONLY|O_BINARY,0);
	if(fd2<0){
	    perror("open");
	}
	else {
	    char buf[4096];
	    ssize_t len;
	    len = read(fd2,buf,sizeof(buf)-1);
	    if(len>0){
		buf[len] = 0;		// be sure it is null terminated
		if(strncmp(buf,"HTTP/1.1 ",9)==0){
		    /* Looks like a HTTP response. Split it.
		     * We do this with memmap  because, quite frankly, it's easier.
		     */
		    struct stat st;
		    if(fstat(fd2,&st)==0){
			void *base = mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd2,0);
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
	    close(fd2);
	}
    }

    if(demux.xreport){
	demux.xreport->push(fileobject_str);
	if(flow_pathname.size()) demux.xreport->xmlout(filename_str,flow_pathname);
	demux.xreport->xmlout(filesize_str,bytes_processed);
	
	std::stringstream attrs;
	attrs << "startime='" << xml::to8601(myflow.tstart) << "' ";
	attrs << "endtime='"  << xml::to8601(myflow.tlast)  << "' ";
	attrs << "src_ipn='"  << myflow.src << "' ";
	attrs << "dst_ipn='"  << myflow.dst << "' ";
	attrs << "packets='"  << myflow.packet_count << "' ";
	attrs << "srcport='"  << myflow.sport << "' ";
	attrs << "dstport='"  << myflow.dport << "' ";
	attrs << "family='"   << (int)myflow.family << "' ";
	if(out_of_order_count) attrs << "out_of_order_count='" << out_of_order_count << "' ";
	if(violations)         attrs << "violations='" << violations << "' ";
	
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


/* Closes the file belonging to a flow.
 * Don't take it out of the map --- we're still thinking about it.
 * Don't reset pos; we will keep track of where we are, even if the file is not open
 */
void tcpip::close_file()
{
    if (fd>=0){
	struct timeval times[2];
	times[0] = myflow.tstart;
	times[1] = myflow.tstart;

	DEBUG(5) ("%s: closing file", flow_pathname.c_str());
	/* close the file and remember that it's closed */
#ifdef OLD_CODE
	fflush(fp);		/* flush the file */
#endif
#if defined(HAVE_FUTIMES)
	if(futimes(fd,times)){
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
	close(fd);
	fd = -1;
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

    size_t written = 0;
    if(strip_nonprint){
	for(const u_char *cc = data;cc<data+length;cc++){
	    if(isprint(*cc) || (*cc=='\n') || (*cc=='\r')){
		written += fputc(*cc,stdout);
	    }
	}
    }
    else {
	written = fwrite(data,1,length,stdout);
    }
    if(length != written) std::cerr << "\nwrite error to stdout\n";

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

/*
 * extend_file_and_insert():
 * A handy function for inserting in the middle or beginning of a file.
 *
 * Based on:
 * http://stackoverflow.com/questions/10467711/c-write-in-the-middle-of-a-binary-file-without-overwriting-any-existing-content
 */


#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

static int insert(int fd, size_t inslen)
{
    enum { BUFFERSIZE = 64 * 1024 };
    char buffer[BUFFERSIZE];
    struct stat sb;

    if (fstat(fd, &sb) != 0) return -1;

    /* Move data after offset up by inslen bytes */
    size_t bytes_to_move = sb.st_size;
    off_t read_end_offset = sb.st_size; 
    while (bytes_to_move != 0) {
	ssize_t bytes_this_time = MIN(BUFFERSIZE, bytes_to_move);
	ssize_t rd_off = read_end_offset - bytes_this_time;
	ssize_t wr_off = rd_off + inslen;
	lseek(fd, rd_off, SEEK_SET);
	if (read(fd, buffer, bytes_this_time) != bytes_this_time)
	    return -1;
	lseek(fd, wr_off, SEEK_SET);
	if (write(fd, buffer, bytes_this_time) != bytes_this_time)
	    return -1;
	bytes_to_move -= bytes_this_time;
    }   
    return 0;
}


/* store the contents of this packet to its place in its file
 * This has to handle out-of-order packets as well as writes
 * past the 4GiB boundary. 
 *
 * 2012-10-24 Originally this code simply computed the 32-bit offset
 * from the beginning of the file using the isn. The new version tracks
 * nsn (the expected next sequence number for the open file).
 *
 * A relative seek before the beginning of the file means that we need
 * to insert.  A relative seek more than max_seek means that we have a
 * different flow that needs to be separately handled.
 *
 */
void tcpip::store_packet(const u_char *data, uint32_t length, int32_t delta)
{
    uint32_t insert_bytes=0;
    uint64_t offset = pos+delta;	// where the data will go in absolute byte positions (first byte is pos=0)

    if((int64_t)offset < 0){
	/* We got bytes before the beginning of the TCP connection.
	 * Either this is a protocol violation,
	 * or else we never saw a SYN and we got the ISN wrong.
	 */
	if(seen_syn){
	    DEBUG(2)("packet received with offset %"PRId64"; ignoring",offset);
	    violations++;
	    return;
	}
	insert_bytes = -offset;		// open up this much space
	offset = 0;			// and write the data here
    }


    /* reduce length to write if it goes beyond the number of bytes per flow,
     * but remember to seek out to the actual position after the truncated write...
     */
    ssize_t wlength = length;		// length to write
    if (demux.max_bytes_per_flow){
	if(offset >= demux.max_bytes_per_flow){
	    wlength = 0;
	} 
	if(offset < demux.max_bytes_per_flow &&  offset+length > demux.max_bytes_per_flow){
	    DEBUG(2) ("packet truncated by max_bytes_per_flow on %s", flow_pathname.c_str());
	    wlength = demux.max_bytes_per_flow - offset;
	}
	omitted_bytes += length-wlength;
    }

    /* if we don't have a file open for this flow, try to open it.
     * return if the open fails.  Note that we don't have to explicitly
     * save the return value because open_tcpfile() puts the file pointer
     * into the structure for us.
     */
    if (fd < 0 && wlength>0) {
	if (demux.open_tcpfile(this)) {
	    DEBUG(1)("unable to open TCP file %s",flow_pathname.c_str());
	    return;
	}
    }
    
    if(insert_bytes>0){
	if(fd>=0) insert(fd,insert_bytes);
	isn -= insert_bytes;		// it's really earlier
	lseek(fd,(off_t)0,SEEK_SET);	// put at the beginning
	pos = 0;
	nsn = isn+1;
	out_of_order_count++;
	DEBUG(25)("%s: insert(0,%d); lseek(%d,0,SEEK_SET) out_of_order_count=%"PRId64,
		  flow_pathname.c_str(), insert_bytes,
		  fd,out_of_order_count);
    }
	

    /* if we're not at the correct point in the file, seek there */
    if (offset != pos) {
	if(fd>=0) lseek(fd,(off_t)delta,SEEK_CUR);
	if(delta<0) out_of_order_count++; // only increment for backwards seeks
	DEBUG(25)("%s: lseek(%d,%d,SEEK_CUR) out_of_order_count=%"PRId64,
		  flow_pathname.c_str(), fd,(int)delta,out_of_order_count);
	pos += delta;			// where we are now
	nsn += delta;			// what we expect the nsn to be now
    }
    
    /* write the data into the file */
    DEBUG(25) ("%s: writing %ld bytes @%"PRId64, flow_pathname.c_str(), (long) wlength, offset);
    
    if(fd>=0){
	if (write(fd,data, wlength) != wlength) {
	    DEBUG(1) ("write to %s failed: ", flow_pathname.c_str());
	    if (debug_level >= 1) perror("");
	}
	if(wlength != length){
	    lseek(fd,length-wlength,SEEK_CUR); // seek out the space we didn't write
	}
    }
    pos += length;
    nsn += length;			// expected next sequence number

    if (out_of_order_count==0 && omitted_bytes==0 && md5){
	MD5Update(md5,data,length);
    }

#ifdef DEBUG_REOPEN_LOGIC
    /* For debugging, force this connection closed */
    demux.close_tcpip(this);			
#endif
}

