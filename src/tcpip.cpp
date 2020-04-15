/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * Modified by Greg Drew to add support for creating a packet time / data index
 * which allows mapping bytes in the flow back to their relative arrival time.
 * This is very useful in reassembling inherently bidirectional conversations
 * such as chat or telnet sessions.  --GDD
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#pragma GCC diagnostic ignored "-Weffc++"
#pragma GCC diagnostic ignored "-Wshadow"


/* Create a new tcp object.
 * 
 * Creating a new object creates a new passive TCP/IP decoder.
 * It will *NOT* append to a flow that is already on the disk or in memory.
 *
 * called from tcpdemux::create_tcpip()
 */
tcpip::tcpip(tcpdemux &demux_,const flow &flow_,be13::tcp_seq isn_):
    demux(demux_),myflow(flow_),dir(unknown),isn(isn_),nsn(0),
    syn_count(0),fin_count(0),fin_size(0),pos(0),
    flow_pathname(),fd(-1),file_created(false),
    flow_index_pathname(),idx_file(),
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

void tcpip::dump_xml(class dfxml_writer *xreport,const std::string &xmladd)
{
    static const std::string fileobject_str("fileobject");
    static const std::string filesize_str("filesize");
    static const std::string filename_str("filename");
    static const std::string tcpflow_str("tcpflow");

    xreport->push(fileobject_str);
    if(flow_pathname.size()) xreport->xmlout(filename_str,flow_pathname);

    xreport->xmlout(filesize_str,last_byte);
	
    std::stringstream attrs;
    attrs << "startime='" << dfxml_writer::to8601(myflow.tstart) << "' ";
    attrs << "endtime='"  << dfxml_writer::to8601(myflow.tlast)  << "' ";
    if(myflow.has_mac_daddr()) attrs << "mac_daddr='" << macaddr(myflow.mac_daddr) << "' ";
    if(myflow.has_mac_saddr()) attrs << "mac_saddr='" << macaddr(myflow.mac_saddr) << "' ";
    attrs << "family='"   << (int)myflow.family << "' ";
    attrs << "src_ipn='"  << ipaddr_prn(myflow.src, myflow.family) << "' ";
    attrs << "dst_ipn='"  << ipaddr_prn(myflow.dst, myflow.family) << "' ";
    attrs << "srcport='"  << myflow.sport << "' ";
    attrs << "dstport='"  << myflow.dport << "' ";
    attrs << "packets='"  << myflow.packet_count << "' ";
    if(out_of_order_count) attrs << "out_of_order_count='" << out_of_order_count << "' ";
    if(violations)         attrs << "violations='" << violations << "' ";
    attrs << "len='"      << myflow.len << "' ";
    if(myflow.len != myflow.caplen) attrs << "caplen='"   << myflow.caplen << "' ";
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
    delete seen;                        // no need to check to see if seen is null or not.
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

	DEBUG(5) ("%s: closing file in tcpip::close_file", flow_pathname.c_str());
	/* close the file and remember that it's closed */
#if defined(HAVE_FUTIMES)
        /* fix microseconds if they are invalid */
        for ( int i=0; i<2; i++){
            if ( times[i].tv_usec < 0 || times[i].tv_usec >= 1000000 ){
                times[i].tv_usec = 0;
            }
        }
	if (futimes(fd,times)){
	    fprintf(stderr,"%s: futimes(fd=%d,[%ld:%ld,%ld:%ld])\n",
                    strerror(errno),fd,
                    times[0].tv_sec,times[1].tv_usec,
                    times[1].tv_sec,times[1].tv_usec);
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
	demux.open_flows.erase(this);           // we are no longer open
    }
    // Also close the flow_index file, if flow indexing is in use --GDD
    if(demux.opt.output_packet_index && idx_file.is_open()){
    	idx_file.close();
    }
    //std::cerr << "close_file1 " << *this << "\n";
}

/*
 * Opens the file transcript file (creating file if necessary).
 * Called by store_packet()
 * Does not change pos.
 */

int tcpip::open_file()
{
	int create_idx_needed = false;
    if(fd<0){
        //std::cerr << "open_file0 " << ct << " " << *this << "\n";
        /* If we don't have a filename, create the flow */
        if(flow_pathname.size()==0) {
            flow_pathname = myflow.new_filename(&fd,O_RDWR|O_BINARY|O_CREAT|O_EXCL,0666);
            file_created = true;		// remember we made it
            create_idx_needed = true;	// We created a new stream, so we need to create a new flow file. --GDD
            DEBUG(5) ("%s: created new file",flow_pathname.c_str());
        } else {
            /* open an existing flow */
            fd = demux.retrying_open(flow_pathname,O_RDWR | O_BINARY | O_CREAT,0666);
            lseek(fd,pos,SEEK_SET);  
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
        demux.open_flows.push_back(this);
        if(demux.open_flows.size() > demux.max_open_flows) demux.max_open_flows = demux.open_flows.size();
        //std::cerr << "open_file1 " << *this << "\n";
    }
    if(demux.opt.output_packet_index){
    	//Open the file for the flow index.  We don't do this if the flow file could not be
    	//	opened.  The file must be opened for append, in case this is a reopen.  The filename
    	//	standard is the flow name followed by ".findx", which google currently says does not
    	//	conflict with anything major.
    	flow_index_pathname = flow_pathname + ".findx";
    	DEBUG(10)("opening index file: %s",flow_index_pathname.c_str());
    	if(create_idx_needed){
    		//New flow file, even if there was an old one laying around --GDD
    		idx_file.open(flow_index_pathname.c_str(),std::ios::trunc|std::ios::in|std::ios::out);
    	}else{
    		//Use existing flow file --GDD
    		idx_file.open(flow_index_pathname.c_str(),std::ios::ate|std::ios::in|std::ios::out);
    	}
    	if(idx_file.bad()){
    		perror(flow_index_pathname.c_str());
    		// Be nice and be sure the flow has been closed in the demultiplexer.
    		// demux.close_tcpip_fd(this);  Need to fix this.  Also, when called, it will
    		// have to differentiate the fact that the open fd cound only needs to be
    		// decremented by one and not by 2.--GDD
    		return -1;
    	}

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

    if(demux.opt.max_bytes_per_flow>=0){
        uint64_t max_bytes_per_flow = (uint64_t)demux.opt.max_bytes_per_flow;

	if(last_byte > max_bytes_per_flow) return; /* too much has been printed */
	if(length > max_bytes_per_flow - last_byte){
	    length = max_bytes_per_flow - last_byte; /* can only output this much */
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

    if(flow_pathname.size()==0) flow_pathname = myflow.filename(0, false);
    if (demux.opt.use_color) fputs(dir==dir_cs ? color[1] : color[2], stdout);
    if (demux.opt.suppress_header == 0 && demux.opt.output_json == 0){
        printf("%s: ", flow_pathname.c_str());
        if(demux.opt.output_hex) putchar('\n');
    }

    size_t written = 0;
    if(demux.opt.output_hex){
        const size_t bytes_per_line = 32;
        size_t max_spaces = 0;
        for(u_int i=0;i<length;i+=bytes_per_line){
            size_t spaces=0;
            
            /* Print the offset */
            char b[64];
            size_t count = snprintf(b,sizeof(b),"%04x: ",(int)i);
            if(fwrite(b,1,count,stdout)!=count){
	      perror("fwrite");
	    }
            spaces += count;
            
            /* Print the hext bytes */
            for(size_t j=0;j<bytes_per_line && i+j<length ;j++){
                unsigned char ch = data[i+j];
                fprintf(stdout,"%02x",ch);  spaces += 2;
                if(j%2==1){
                    fputc(' ',stdout);
                    spaces += 1;
                }
            }
            /* space out to where the ASCII region is */
            if(spaces>max_spaces) max_spaces=spaces;
            for(;spaces<max_spaces;spaces++){
                fputc(' ',stdout);
            }
            putchar(' ');
            /* Print the ascii */
            for(size_t j=0;j<bytes_per_line && i+j<length;j++){
                unsigned char ch = data[i+j];
                if(ch>=' ' && ch<='~') fputc(ch,stdout);
                else fputc('.',stdout);
            }
            fputc('\n',stdout);
        }
        written = length;               // just fake it.
    } else if (demux.opt.output_json) {
        // {
        //     "src_host": "192.168.0.1",
        //     "src_port": 1234,
        //     "dst_host": "1.1.1.1",
        //     "dst_port": 80,
        //     "payload" : [...]
        // }    

        std::string hoststr = std::string();

        putchar('{');   
        printf("\"src_host\":\"");

        size_t src_pos = 0;
        size_t src_end_pos = 0;
        size_t src_pos_counter = 0;

        size_t pathname_len = flow_pathname.length();
        for(size_t i = 0; i < pathname_len; ++i) {
            if(flow_pathname[i] == '.') {
                src_pos_counter++;
                printf("%d%s", atoi(hoststr.c_str()), (src_pos_counter != 4 ? "." : ""));
                hoststr.clear();
            } else {
                hoststr = hoststr + flow_pathname[i];
            }
            if(src_pos_counter == 4) {
                src_pos = i;
                break;
            }
        }
        src_end_pos = src_pos;
        for(;src_end_pos < pathname_len; ++src_end_pos) {
            if(flow_pathname[src_end_pos] == '-') {
                break;
            }
        }
        printf("\",\"src_port\":%d,\"dst_host\":\"", atoi(flow_pathname.substr(src_pos + 1, src_end_pos - src_pos).c_str()));
        
        size_t dst_pos = src_end_pos + 1;
        size_t dst_end_pos = dst_pos;
        size_t dst_pos_counter = 0;
        
        for(size_t i = dst_pos; i < pathname_len; ++i) {
              if(flow_pathname[i] == '.') {
                dst_pos_counter++;
                printf("%d%s", atoi(hoststr.c_str()), (dst_pos_counter != 4 ? "." : ""));
                hoststr.clear();
            } else {
                hoststr = hoststr + flow_pathname[i];
            }
            if(dst_pos_counter == 4) {
                dst_pos = i;
                break;
            }
        }
        dst_end_pos = dst_pos;
        for(;dst_end_pos < pathname_len; ++dst_end_pos) {
            if(flow_pathname[dst_end_pos] == '-') {
                break;
            }
        }
        printf("\",\"dst_port\":%d,\"payload\": [", atoi(flow_pathname.substr(dst_pos + 1, dst_end_pos - dst_pos).c_str()));

        for(size_t i = 0; i < length; ++i) {
            printf("%d%s", data[i], (i != length - 1 ? "," : "]}"));
        }
    } else if (demux.opt.output_strip_nonprint) {
	    for(const u_char *cc = data;cc<data+length;cc++){
	    if(isprint(*cc) || (*cc=='\n') || (*cc=='\r')){
                int ret = fputc(*cc,stdout);
                if(ret==EOF){
                    std::cerr << "EOF on write to stdout\n";
                    exit(1);
                
                }
	    }
	    else fputc('.',stdout);
            written += 1; // treat even unprintable characters as "written". It
                          // really means "processed"
        }
	} else {
	    written = fwrite(data,1,length,stdout);
        if(length != written) std::cerr << "\nwrite error to stdout (" << length << "!=" << written << ") \n";
    }

    last_byte += length;

    if (demux.opt.use_color) printf("\033[0m");

    if (! demux.opt.console_output_nonewline) putchar('\n');
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
    enum { BUFFERSIZE = 64 * 1024 };
    char buffer[BUFFERSIZE];
    struct stat sb;

    DEBUG(100)("shift_file(%d,%d)",fd,(int)inslen);

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
void tcpip::store_packet(const u_char *data, uint32_t length, int32_t delta,struct timeval ts)
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
	    DEBUG(2)("packet received with offset %" PRId64 "; ignoring",offset);
	    violations++;
	    return;
	}
	insert_bytes = -offset;		// open up this much space
	offset = 0;			// and write the data here
    }

    /* reduce length to write if it goes beyond the number of bytes per flow,
     * but remember to seek out to the actual position after the truncated write...
     */
    uint32_t wlength = length;		// length to write
    if (demux.opt.max_bytes_per_flow >= 0){
        uint64_t max_bytes_per_flow = (uint64_t)demux.opt.max_bytes_per_flow;

	if(offset >= max_bytes_per_flow){
	    wlength = 0;
	} 
	if(offset < max_bytes_per_flow &&  offset+length > max_bytes_per_flow){
	    DEBUG(2) ("packet truncated by max_bytes_per_flow on %s", flow_pathname.c_str());
	    wlength = max_bytes_per_flow - offset;
	}
    }

    /* if we don't have a file open for this flow, try to open it.
     * return if the open fails.  Note that we don't have to explicitly
     * save the return value because open_tcpfile() puts the file pointer
     * into the structure for us.
     */
    if (fd < 0) {
	if (open_file()) {
	    DEBUG(1)("unable to open TCP file %s  fd=%d  wlength=%d",
                     flow_pathname.c_str(),fd,(int)wlength);
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
	DEBUG(25)("%s: insert(0,%d); lseek(%d,0,SEEK_SET) out_of_order_count=%" PRId64,
		  flow_pathname.c_str(), insert_bytes,
		  fd,out_of_order_count);

        /* TK: If we have seen packets, everything in the recon set needs to be shifted as well.*/
        delete seen;
        seen = 0;
    }

    /* if we're not at the correct point in the file, seek there */
    if (offset != pos) {
        /* Check for a keepalive */
        if(delta == -1 && length == 1) {
            DEBUG(25)("%s: RFC1122 keepalive detected and ignored",flow_pathname.c_str());
            return;
        }

	if(fd>=0) lseek(fd,(off_t)delta,SEEK_CUR);
	if(delta<0) out_of_order_count++; // only increment for backwards seeks
	DEBUG(25)("%s: lseek(%d,%d,SEEK_CUR) offset=%" PRId64 " pos=%" PRId64 " out_of_order_count=%" PRId64,
		  flow_pathname.c_str(), fd,(int)delta,offset,pos,out_of_order_count);
	pos += delta;			// where we are now
	nsn += delta;			// what we expect the nsn to be now
    }
    
    /* write the data into the file */
    DEBUG(25) ("%s: %s write %ld bytes @%" PRId64,
               flow_pathname.c_str(),
               fd>=0 ? "will" : "won't",
               (long) wlength, offset);
    
    if(fd>=0){
      if ((uint32_t)write(fd,data, wlength) != wlength) {
	    DEBUG(1) ("write to %s failed: ", flow_pathname.c_str());
	    if (debug >= 1) perror("");
	}
	// Write to the index file if needed.  Note, index file is sorted before close, so no need to jump around --GDD
		if (demux.opt.output_packet_index && idx_file.is_open()) {
			idx_file << offset << "|" << ts.tv_sec << "." << std::setw(6) << std::setfill('0') << ts.tv_usec << "|"
					<< wlength << "\n";
			if (idx_file.bad()){
				DEBUG(1)("write to index file %s failed: ",flow_index_pathname.c_str());
				if(debug >= 1){
					perror("");
				}
			}
		}
	if(wlength != length){
	    off_t p = lseek(fd,length-wlength,SEEK_CUR); // seek out the space we didn't write
            DEBUG(100)("   lseek(%" PRId64 ",SEEK_CUR)=%" PRId64,(int64_t)(length-wlength),(int64_t)p);
	}
    }

    /* Update the database of bytes that we've seen */
    if(seen) update_seen(seen,pos,length);

    /* Update the position in the file and the next expected sequence number */
    pos += length;
    nsn += length;			// expected next sequence number

    if(pos>last_byte) last_byte = pos;

    if(debug>=100){
        uint64_t rpos = lseek(fd,(off_t)0,SEEK_CUR);
        DEBUG(100)("    pos=%" PRId64 "  lseek(fd,0,SEEK_CUR)=%" PRId64,pos,rpos);
        assert(pos==rpos);
    }

#ifdef DEBUG_REOPEN_LOGIC
    /* For debugging, force this connection closed */
    demux.close_tcpip_fd(this);			
#endif
}

/*
 * Compare two index strings and return the result.  Called by
 * the vector::sort in sort_index.
 * --GDD
 */
bool tcpip::compare(std::string a, std::string b){
	std::stringstream ss_a(a),ss_b(b);
	long a_l,b_l;

	ss_a >> a_l;
	ss_b >> b_l;
	return a_l < b_l;
}

/*
 * Sort an index file (presumably from this object) if file indexing is
 * turned on and the file exists.  Index files may be out of order due
 * to the arrival of out of order packets.  It is cheaper to reorder them
 * one time at the end of processing than it is to continually keep them
 * in order.
 * --GDD
 */
void tcpip::sort_index(std::fstream *ix_file) {

	std::vector<std::string> idx;
	std::string line;

	if (demux.opt.output_packet_index) {
		if (!(idx_file.good() && idx_file.is_open())) {
			DEBUG(5)("Skipping index file sort.  Unusual behavior.\n");
			return; //Nothing to do
		}
		//Make sure we are at the beginning.
		ix_file->clear();
		ix_file->seekg(0);
		do {
			*ix_file >> line;
			if (!ix_file->eof()) {
				idx.push_back(line);
			}
		} while (ix_file->good());
		std::sort(idx.begin(), idx.end(), &tcpip::compare);
		ix_file->clear();
		ix_file->seekg(0);
		for (std::vector<std::string>::iterator s = idx.begin(); s != idx.end();
				s++) {
			*ix_file << *s << "\n";
		}
	}
}

/*
 * Convenience function to cause the local index file to be sorted.
 * --GDD
 */
void tcpip::sort_index(){
	tcpip::sort_index(&(this->idx_file));
}

#pragma GCC diagnostic ignored "-Weffc++"
#pragma GCC diagnostic ignored "-Wshadow"

/* Note --- Turn off warning so that creating the seen() map doesn't throw an error */
//#pragma GCC diagnostic ignored "-Weffc++"
