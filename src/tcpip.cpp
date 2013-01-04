/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"
#include "bulk_extractor_i.h"

#include <iostream>
#include <sstream>

#pragma GCC diagnostic ignored "-Weffc++"
#pragma GCC diagnostic ignored "-Wshadow"
/* Create a new tcp object.
 * 
 * Creating a new object creates a new passive TCP/IP decoder.
 * It will *NOT* append to a flow that is already on the disk or in memory.
 */
tcpip::tcpip(tcpdemux &demux_,const flow &flow_,tcp_seq isn_):
    demux(demux_),myflow(flow_),dir(unknown),isn(isn_),nsn(0),
    syn_count(0),fin_count(0),fin_size(0),pos(0),
    flow_pathname(),fd(-1),file_created(false),
    seen(new recon_set()),
    last_byte(),
    last_packet_number(),out_of_order_count(0),violations(0)
{
}


uint32_t tcpip::seen_bytes()
{
    if(seen) return seen->size();
    return 0;
}

void tcpip::dump_seen()
{
    if(seen){
        for(recon_set::const_iterator it = seen->begin(); it!=seen->end(); it++){
            std::cerr << *it << ", ";
        }
        std::cerr << std::endl;
    }
}

void tcpip::dump_xml(class xml *xreport,const std::string &xmladd)
{
    static const std::string fileobject_str("fileobject");
    static const std::string filesize_str("filesize");
    static const std::string filename_str("filename");
    static const std::string tcpflow_str("tcpflow");

    xreport->push(fileobject_str);
    if(flow_pathname.size()) xreport->xmlout(filename_str,flow_pathname);

    xreport->xmlout(filesize_str,last_byte);
	
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
	
    xreport->xmlout(tcpflow_str,"",attrs.str(),false);
    if(xmladd.size()>0) xreport->xmlout("",xmladd,"",false);
    xreport->pop();
    xreport->flush();
}


/**
 * Destructor is called when flow is closed.
 * It implements "after" processing.
 * This should only be called from remove_flow() or remove_all_flows()
 * when a flow is deleted.
 */
tcpip::~tcpip()
{
    assert(fd<0);                       // file must be closed
    if(seen) delete seen;
}

#pragma GCC diagnostic warning "-Weffc++"
#pragma GCC diagnostic warning "-Wshadow"


/****************************************************************
 ** SAVE FILE MANAGEMENT
 ****************************************************************
 *
 * Unlike the tcp/ip object, which is created once, the file can be opened, closed, and
 * re-opened depending on the availability of file handles.
 * 
 * Closing the file does not delete the tcp/ip object.
 */


/* Closes the file belonging to a flow.
 * Does not take tcpip out of flow database.
 * Does not change pos. 
 */
void tcpip::close_file()
{
    if (fd>=0){
	struct timeval times[2];
	times[0] = myflow.tstart;
	times[1] = myflow.tstart;

	DEBUG(5) ("%s: closing file", flow_pathname.c_str());
	/* close the file and remember that it's closed */
#if defined(HAVE_FUTIMES)
	if(futimes(fd,times)){
	    fprintf(stderr,"%s: futimes(fd=%d)\n",strerror(errno),fd);
            abort();
	}
#elif defined(HAVE_FUTIMENS) 
	struct timespec tstimes[2];
	for(int i=0;i<2;i++){
	    tstimes[i].tv_sec = times[i].tv_sec;
	    tstimes[i].tv_nsec = times[i].tv_usec * 1000;
	}
	if(futimens(fd,tstimes)){
	    perror("futimens(fd=%d)",fd);
	}
#endif
	close(fd);
	fd = -1;
    }
    demux.open_flows.erase(this);           // we are no longer open
}

/*
 * Opens the file transcript file (creating file if necessary).
 * Called by store_packet()
 * Does not change pos.
 */

int tcpip::open_file()
{
    if(fd<0){

        /* If we don't have a filename, create the flow */
        if(flow_pathname.size()==0) {
            flow_pathname = myflow.new_filename(&fd,O_RDWR|O_BINARY|O_CREAT,0666);
            file_created = true;		// remember we made it
            DEBUG(5) ("%s: created new file",flow_pathname.c_str());
        } else {
            /* open an existing flow */
            fd = demux.retrying_open(flow_pathname,O_RDWR | O_BINARY | O_CREAT,0666);
            DEBUG(5) ("%s: opening existing file", flow_pathname.c_str());
        }
        
        /* If the file isn't open at this point, there's a problem */
        if (fd < 0 ) {
            /* we had some problem opening the file -- set FINISHED so we
             * don't keep trying over and over again to reopen it
             */
            perror(flow_pathname.c_str());
            return -1;
        }
        /* Remember that we have this open */
        demux.open_flows.insert(this);
    }
    return 0;
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

    if(demux.opt.max_bytes_per_flow>0){
	if(last_byte > demux.opt.max_bytes_per_flow) return; /* too much has been printed */
	if(length > demux.opt.max_bytes_per_flow - last_byte){
	    length = demux.opt.max_bytes_per_flow - last_byte; /* can only output this much */
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

    if (demux.opt.use_color) fputs(dir==dir_cs ? color[1] : color[2], stdout);
    if (demux.opt.suppress_header == 0) printf("%s: ", flow_pathname.c_str());

    size_t written = 0;
    if(demux.opt.strip_nonprint){
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

    last_byte += length;

    if (demux.opt.use_color) printf("\033[0m");

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

static int shift_file(int fd, size_t inslen)
{
    abort();

    enum { BUFFERSIZE = 64 * 1024 };
    char buffer[BUFFERSIZE];
    struct stat sb;

    if (fstat(fd, &sb) != 0) return -1;

    /* Move data after offset up by inslen bytes */
    size_t bytes_to_move = sb.st_size;
    off_t read_end_offset = sb.st_size; 
    while (bytes_to_move != 0) {
	ssize_t bytes_this_time = bytes_to_move < BUFFERSIZE ? bytes_to_move : BUFFERSIZE ;
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

#pragma GCC diagnostic ignored "-Weffc++"
void update_seen(recon_set *seen,uint64_t pos,uint32_t length)
{
    if(seen){
        (*seen) += boost::icl::discrete_interval<uint64_t>::closed(pos,pos+length-1);
    }
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
 * called from tcpdemux::process_tcp_packet()
 */
void tcpip::store_packet(const u_char *data, uint32_t length, int32_t delta)
{
    if(length==0) return;               // no need to do anything

    uint32_t insert_bytes=0;
    uint64_t offset = pos+delta;	// where the data will go in absolute byte positions (first byte is pos=0)

    if((int64_t)offset < 0){
	/* We got bytes before the beginning of the TCP connection.
	 * Either this is a protocol violation,
	 * or else we never saw a SYN and we got the ISN wrong.
	 */
	if(syn_count>0){
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
    if (demux.opt.max_bytes_per_flow){
	if(offset >= demux.opt.max_bytes_per_flow){
	    wlength = 0;
	} 
	if(offset < demux.opt.max_bytes_per_flow &&  offset+length > demux.opt.max_bytes_per_flow){
	    DEBUG(2) ("packet truncated by max_bytes_per_flow on %s", flow_pathname.c_str());
	    wlength = demux.opt.max_bytes_per_flow - offset;
	}
    }

    /* if we don't have a file open for this flow, try to open it.
     * return if the open fails.  Note that we don't have to explicitly
     * save the return value because open_tcpfile() puts the file pointer
     * into the structure for us.
     */
    if (fd < 0 && wlength>0) {
	if (open_file()) {
	    DEBUG(1)("unable to open TCP file %s",flow_pathname.c_str());
	    return;
	}
    }
    
    /* Shift the file now if we were going shift it */

    if(insert_bytes>0){
	if(fd>=0) shift_file(fd,insert_bytes);
	isn -= insert_bytes;		// it's really earlier
	lseek(fd,(off_t)0,SEEK_SET);	// put at the beginning
	pos = 0;
	nsn = isn+1;
	out_of_order_count++;
	DEBUG(25)("%s: insert(0,%d); lseek(%d,0,SEEK_SET) out_of_order_count=%"PRId64,
		  flow_pathname.c_str(), insert_bytes,
		  fd,out_of_order_count);
        /* right now we don't know how to deal with this issue --- */
        if(seen){
            delete seen;
            seen = 0;
        }
    }

    /* if we're not at the correct point in the file, seek there */
    if (offset != pos) {
	if(fd>=0) lseek(fd,(off_t)delta,SEEK_CUR);
	if(delta<0) out_of_order_count++; // only increment for backwards seeks
	DEBUG(25)("%s: lseek(%d,%d,SEEK_CUR) offset=%"PRId64" pos=%"PRId64" out_of_order_count=%"PRId64,
		  flow_pathname.c_str(), fd,(int)delta,offset,pos,out_of_order_count);
	pos += delta;			// where we are now
	nsn += delta;			// what we expect the nsn to be now
    }
    
    /* write the data into the file */
    DEBUG(25) ("%s: writing %ld bytes @%"PRId64, flow_pathname.c_str(), (long) wlength, offset);
    
    if(fd>=0){
	if (write(fd,data, wlength) != wlength) {
	    DEBUG(1) ("write to %s failed: ", flow_pathname.c_str());
	    if (debug >= 1) perror("");
	}
	if(wlength != length){
	    lseek(fd,length-wlength,SEEK_CUR); // seek out the space we didn't write
	}
    }

    /* Update the database of bytes that we've seen */
    if(seen) update_seen(seen,pos,length);

    /* Update the position in the file and the next expected sequence number */
    pos += length;
    nsn += length;			// expected next sequence number

    if(pos>last_byte) last_byte = pos;

#ifdef DEBUG_REOPEN_LOGIC
    /* For debugging, force this connection closed */
    demux.close_tcpip_fd(this);			
#endif
}

#pragma GCC diagnostic ignored "-Weffc++"
#pragma GCC diagnostic ignored "-Wshadow"

/* Note --- Turn off warning so that creating the seen() map doesn't throw an error */
//#pragma GCC diagnostic ignored "-Weffc++"

/*
 * byte-parsing helper functions
 */
bool tcpip::tcp_from_bytes(const uint8_t *bytes, const uint64_t len, struct tcphdr &tcp,
        const uint8_t *&payload, uint64_t &payload_len)
{
    if(len < sizeof(struct tcphdr)) {
        return false;
    }

    const struct tcphdr *tcp_header = (struct tcphdr *) bytes;

    uint64_t header_len = tcp_header->th_off * 4;
    if(len > header_len) {
        payload = bytes + header_len;
    }
    else {
        payload = NULL;
    }

    tcp = *tcp_header;

    return true;
}

bool tcpip::tcp_from_ip_bytes(const uint8_t *bytes, const uint64_t len, struct tcphdr &tcp,
        const uint8_t *&payload, uint64_t &payload_len)
{
    struct ip ip4;
    struct private_ip6_hdr ip6;
    uint64_t tcp_len = 0;
    const uint8_t *tcp_bytes;

    if(ip4_from_bytes(bytes, len, ip4, tcp_bytes, tcp_len)) {
        if(ip4.ip_p != IPPROTO_TCP) {
            return false;
        }
    }
    else if(ip6_from_bytes(bytes, len, ip6, tcp_bytes, tcp_len)) {
        if(ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
            return false;
        }
    }
    else {
        return false;
    }

    if(!tcp_from_bytes(tcp_bytes, tcp_len, tcp, payload, payload_len)) {
        return false;
    }

    return true;
}

bool tcpip::ip4_from_bytes(const uint8_t *bytes, const uint64_t len, struct ip &ip,
    const uint8_t *&payload, uint64_t &payload_len)
{
    if(len < sizeof(struct ip)) {
        return false;
    }

    const struct ip *ip_header = (struct ip *) bytes;

    if(ip_header->ip_v != 4) {
        return false;
    }

    uint64_t header_len = ip_header->ip_hl * 4;
    if(len > header_len) {
        payload = bytes + header_len;
        payload_len = len - header_len;
    }
    else {
        payload = NULL;
        payload_len = 0;
    }

    ip = *ip_header;

    return true;
}

bool tcpip::ip6_from_bytes(const uint8_t *bytes, const uint64_t len, struct private_ip6_hdr &ip,
        const uint8_t *&payload, uint64_t &payload_len)
{
    if(len < sizeof(private_ip6_hdr)) {
        return false;
    }

    const struct ip *ip_header = (struct ip *) bytes;

    if(ip_header->ip_v != 6) {
        return false;
    }

    const struct private_ip6_hdr *ip6_header = (struct private_ip6_hdr *) bytes;

    uint64_t header_len = sizeof(private_ip6_hdr);

    if(len > header_len) {
        payload = bytes + header_len;
        payload_len = len - header_len;
    }
    else {
        payload = NULL;
        payload_len = 0;
    }

    ip = *ip6_header;

    return true;
}
