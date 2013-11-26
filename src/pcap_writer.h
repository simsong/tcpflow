/*
 * pcap_writer.h:
 * 
 * A class for writing pcap files
 */

#ifndef HAVE_PCAP_WRITER_H
#define HAVE_PCAP_WRITER_H
class pcap_writer {
    /* These are not implemented */
    pcap_writer &operator=(const pcap_writer &that);
    pcap_writer(const pcap_writer &t);
    class write_error: public std::exception {
        virtual const char *what() const throw() {
            return "write error in pcap_write";
        }
    };
    
    enum {PCAP_RECORD_HEADER_SIZE = 16,
          PCAP_MAX_PKT_LEN = 65535,      // wire shark may reject larger
          PCAP_HEADER_SIZE = 4+2+2+4+4+4+4,
    };
    FILE *fcap;                         // where file is written
    void write_bytes(const uint8_t * const val, size_t num_bytes) {
        size_t count = fwrite(val,1,num_bytes,fcap);
        if (count != num_bytes) throw new write_error();
    }
    void write2(const uint16_t val) {
        size_t count = fwrite(&val,1,2,fcap);
        if (count != 2)  throw new write_error();
    }
    void write4(const uint32_t val) {
        size_t count = fwrite(&val,1,4,fcap);
        if (count != 4) throw new write_error();
    }
    void open(const std::string &fname) {
        fcap = fopen(fname.c_str(),"wb"); // write the output
        if(fcap==0) throw new write_error();
    }
    void write_header(){
        write4(0xa1b2c3d4);
        write2(2);			// major version number
        write2(4);			// minor version number
        write4(0);			// time zone offset; always 0
        write4(0);			// accuracy of time stamps in the file; always 0
        write4(PCAP_MAX_PKT_LEN);	// snapshot length
        write4(DLT_EN10MB);             // link layer encapsulation
    }
    void copy_header(const std::string &ifname){
        /* assert byte order is correct */
        FILE *f2 = fopen(ifname.c_str(),"rb");
        if(f2==0) throw new write_error();
        u_char buf[PCAP_HEADER_SIZE];
        if(fread(buf,1,sizeof(buf),f2)!=sizeof(buf)) throw new write_error();
        if((buf[0]!=0xd4) || (buf[1]!=0xc3) || (buf[2]!=0xb2) || (buf[3]!=0xa1)){
            std::cout << "pcap file " << ifname << " is in wrong byte order. Cannot continue.\n";
            throw new write_error();
        }
        if(fwrite(buf,1,sizeof(buf),fcap)!=sizeof(buf)) throw new write_error();
        if(fclose(f2)!=0) throw new write_error();
    }
    pcap_writer():fcap(0){}

public:
    static pcap_writer *open_new(const std::string &ofname){
        pcap_writer *pcw = new pcap_writer();
        pcw->open(ofname);
        pcw->write_header();
        return pcw;
    }
    static pcap_writer *open_copy(const std::string &ofname,const std::string &ifname){
        pcap_writer *pcw = new pcap_writer();
        pcw->open(ofname);
        pcw->copy_header(ifname);
        return pcw;
    }
    virtual ~pcap_writer(){
        if(fcap) fclose(fcap);
    }
    void writepkt(const struct pcap_pkthdr *h,const u_char *p) {
        /* Write a packet */
        write4(h->ts.tv_sec);		// time stamp, seconds avalue
        write4(h->ts.tv_usec);		// time stamp, microseconds
        write4(h->caplen);
        write4(h->len);
        size_t count = fwrite(p,1,h->caplen,fcap);	// the packet
        if(count!=h->caplen) throw new write_error();
    }
};
    
#endif
