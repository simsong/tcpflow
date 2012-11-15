#include "config.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include "bulk_extractor_i.h"
#include "unicode_escape.h"

extern int debug;

/****************************************************************
 *** SBUF_T
 ****************************************************************/

/**
 *  Map a file; falls back to read if mmap is not available
 */
static std::string U10001C("\xf4\x80\x80\x9c");
sbuf_t *sbuf_t::map_file(const std::string &fname)
{
    int fd = open(fname.c_str(),O_RDONLY,0);
    if(fd<0) return 0;		/* cannot open file */
    return sbuf_t::map_file(fname,fd);
}

sbuf_t *sbuf_t::map_file(const std::string &fname,int fd)
{
    struct stat st;
    if(fstat(fd,&st)){
	close(fd);
	return 0; /* cannot stat */
    }

#ifdef HAVE_MMAP
    uint8_t *buf = (uint8_t *)mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd,0);
    bool should_free  = false;
    bool should_unmap = true;
    bool should_close = true;
#else
    uint8_t *buf = (uint8_t *)malloc(st.st_size);
    if(buf==0){		/* malloc failed */
	return 0;
    }
    if((size_t)read(fd,(void *)buf,st.st_size)!=st.st_size){
	free((void *)buf);		/* read failed */
	return 0;
    }
    close(fd);
    fd = 0;
    bool should_free = true;
    bool should_unmap = false;
    bool should_close = false;
#endif
    sbuf_t *sbuf = new sbuf_t(fname + U10001C,// set the filename followed by U+10001C in UTF-8
			      buf,
			      st.st_size,
			      st.st_size,
			      fd,
			      should_unmap,
			      should_free,
			      should_close);
    return sbuf;
}

/*
 * Returns self or the highest parent of self, whichever is higher
 */
const sbuf_t *sbuf_t::highest_parent() const 
{
    const sbuf_t *hp = this;
    while(hp->parent != 0){
	hp = hp->parent;
    }
    return hp;
}

/**
 * rawdump the sbuf to an ostream.
 */
void sbuf_t::raw_dump(std::ostream &os,uint64_t start,uint64_t len) const
{
    for(uint64_t i=start;i<start+len  && i<bufsize;i++){
	os << buf[i];
    }
}

/**
 * rawdump the sbuf to a file descriptor
 */
void sbuf_t::raw_dump(int fd2,uint64_t start,uint64_t len) const
{
    if(len>bufsize-start) len=bufsize-start; // maximum left
    uint64_t written = ::write(fd2,buf+start,len);
    if(written!=len){
      cerr << "write: cannot write sbuf.\n";
    }
}

static std::string hexch(unsigned char ch)
{
    char buf[4];
    snprintf(buf,sizeof(buf),"%02x",ch);
    return std::string(buf);
}

/**
 * hexdump the sbuf.
 */
void sbuf_t::hex_dump(std::ostream &os,uint64_t start,uint64_t len) const
{
    const size_t bytes_per_line = 32;
    for(uint64_t i=start;i<start+len && i<bufsize;i+=bytes_per_line){
	size_t spaces=0;
	for(size_t j=0;j<bytes_per_line && i+j<bufsize && i+j<start+len;j++){
	    unsigned char ch = (*this)[i+j];
	    os << hexch(ch) << " ";
	    spaces += 3;
	    if(j==bytes_per_line/2){
		os << ' ';
		spaces += 1;
	    }
	}
	for(;spaces<bytes_per_line*3+3;spaces++){
	    os << ' ';
	}
	for(size_t j=0;j<bytes_per_line && i+j<bufsize && i+j<start+len;j++){
	    unsigned char ch = (*this)[i+j];
	    if(ch>=' ' && ch<='~') os << ch;
	    else os << '.';
	}
	os << "\n";
    }
}

/* Write to a file descriptor */
ssize_t sbuf_t::write(int fd_,size_t loc,size_t len) const
{
    if(loc>=bufsize) return 0;		// cannot write
    if(loc+len>bufsize) len=bufsize-loc; // clip at the end
    return ::write(fd_,buf+loc,len);
}

/* Write to a FILE */
ssize_t sbuf_t::write(FILE *f,size_t loc,size_t len) const
{
    if(loc>=bufsize) return 0;		// cannot write
    if(loc+len>bufsize) len=bufsize-loc; // clip at the end
    return ::fwrite(buf+loc,1,len,f);
}

/* Return a substring */
std::string sbuf_t::substr(size_t loc,size_t len) const
{
    if(loc>=bufsize) return std::string("");		// cannot write
    if(loc+len>bufsize) len=bufsize-loc; // clip at the end
    return std::string((const char *)buf+loc,len);
}

/* Return the md5 of a substring */
md5_t sbuf_t::md5(size_t loc,size_t len) const
{
    if(loc>=bufsize) return md5_generator::hash_buf((const unsigned char *)"",0);
    if(loc+len>bufsize) len=bufsize-loc; // clip at the end
    return md5_generator::hash_buf(buf+loc,len);
}

md5_t sbuf_t::md5() const 
{
    return md5(0,pagesize);
}

bool sbuf_t::is_constant(size_t offset,size_t len,uint8_t ch) const // verify that it's constant
{
    while(len>0){
	if(((*this)[offset])!=ch) return false;
	offset++;
	len--;
    }
    return true;
}

void sbuf_t::hex_dump(std::ostream &os) const 
{
    hex_dump(os,0,bufsize);
}

/**
 * Convert a binary blob to a hex representation
 */

#ifndef NSRL_HEXBUF_UPPERCASE
#define NSRL_HEXBUF_UPPERCASE 0x01
#define NSRL_HEXBUF_SPACE2    0x02
#define NSRL_HEXBUF_SPACE4    0x04
#endif


static int hexcharvals[256] = {-1,0};
static const char *hexbuf(char *dst,int dst_len,const unsigned char *bin,int bytes,int flag)
{
    int charcount = 0;
    const char *start = dst;		// remember where the start of the string is
    const char *fmt = (flag & NSRL_HEXBUF_UPPERCASE) ? "%02X" : "%02x";

    if(hexcharvals[0]==-1){
	/* Need to initialize this */
	for(int i=0;i<256;i++){
	    hexcharvals[i] = 0;
	}
	for(int i=0;i<10;i++){
	    hexcharvals['0'+i] = i;
	}
	for(int i=10;i<16;i++){
	    hexcharvals['A'+i-10] = i;
	    hexcharvals['a'+i-10] = i;
	}
    }

    *dst = 0;				// begin with null termination
    while(bytes>0 && dst_len > 3){
	sprintf(dst,fmt,*bin); // convert the next byte
	dst += 2;
	bin += 1;
	dst_len -= 2;
	bytes--;
	charcount++;			// how many characters
	
	if((flag & NSRL_HEXBUF_SPACE2) ||
	   ((flag & NSRL_HEXBUF_SPACE4) && charcount%2==0))
	    *dst++ = ' ';
	    *dst   = '\000';
	    dst_len -= 1;
    }
    return start;			// return the start
}


std::ostream & operator <<(std::ostream &os,const sbuf_t &t){
	char hex[17];
	hexbuf(hex,sizeof(hex),t.buf,8,0);
	os << "sbuf[page_number="   << t.page_number
	   << " pos0=" << t.pos0 << " " << "buf[0..8]=0x" << hex
	   << " bufsize=" << t.bufsize << " pagesize=" << t.pagesize << "]";
	return os;
    }

/**
 * Read the requested number of UTF-8 format string octets including any \0.
 */
void sbuf_t::getUTF8WithQuoting(size_t i, size_t num_octets_requested, std::string &utf8_string) const {
    // clear any residual value
    utf8_string = "";

    if(i>=bufsize) {
        // past EOF
        return;
    }
    if(i+num_octets_requested>bufsize) {
        // clip at EOF
        num_octets_requested = bufsize - i;
    }
    utf8_string = std::string((const char *)buf+i,num_octets_requested);

    // validate or escape utf8_string
    utf8_string = validateOrEscapeUTF8(utf8_string, true, true);
}

/**
 * Read UTF-8 format code octets into string up to but not including \0.
 */
void sbuf_t::getUTF8WithQuoting(size_t i, std::string &utf8_string) const {
    // clear any residual value
    utf8_string = "";

    // read octets
    for (size_t offset=i; offset<bufsize; offset++) {
        uint8_t octet = get8u(offset);

        // stop before \0
        if (octet == 0) {
            // at \0
            break;
        }

        // accept the octet
        utf8_string.push_back(octet);
    }

    // validate or escape utf8_string
    utf8_string = validateOrEscapeUTF8(utf8_string, true, true);
}

/**
 * Read the requested number of UTF-16 format code units into wstring including any \U0000.
 */
void sbuf_t::getUTF16(size_t i, size_t num_code_units_requested, std::wstring &utf16_string) const {
    // clear any residual value
    utf16_string = std::wstring();

    if(i>=bufsize) {
        // past EOF
        return;
    }
    if(i+num_code_units_requested*2+1>bufsize) {
        // clip at EOF
        num_code_units_requested = ((bufsize-1)-i)/2;
    }
    // NOTE: we can't use wstring constructor because we require 16 bits,
    // not whatever sizeof(wchar_t) is.
    // utf16_string = std::wstring((const char *)buf+i,num_code_units_requested);

    // get code units individually
    for (size_t j = 0; j < num_code_units_requested; j++) {
        utf16_string.push_back(get16u(i + j));
    }
}

/**
 * Read UTF-16 format code units into wstring up to but not including \U0000.
 */
void sbuf_t::getUTF16(size_t i, std::wstring &utf16_string) const {
    // clear any residual value
    utf16_string = std::wstring();

    // read the code units
    size_t offset;
    for (offset=i; offset<bufsize-1; offset += 2) {
        uint16_t code_unit = get16u(offset);
        //cout << "sbuf.cpp getUTF16 i: " << i << " code unit: " << code_unit << "\n";

        // stop before \U0000
        if (code_unit == 0) {
            // at \U0000
            break;
        }

        // accept the code unit
        utf16_string.push_back(code_unit);
    }
}

/**
 * Read the requested number of UTF-16 format code units using the specified byte order into wstring including any \U0000.
 */
void sbuf_t::getUTF16(size_t i, size_t num_code_units_requested, byte_order_t bo, std::wstring &utf16_string) const {
    // clear any residual value
    utf16_string = std::wstring();

    if(i>=bufsize) {
        // past EOF
        return;
    }
    if(i+num_code_units_requested*2+1>bufsize) {
        // clip at EOF
        num_code_units_requested = ((bufsize-1)-i)/2;
    }
    // NOTE: we can't use wstring constructor because we require 16 bits,
    // not whatever sizeof(wchar_t) is.
    // utf16_string = std::wstring((const char *)buf+i,num_code_units_requested);

    // get code units individually
    for (size_t j = 0; j < num_code_units_requested; j++) {
        utf16_string.push_back(get16u(i + j, bo));
    }
}

/**
 * Read UTF-16 format code units using the specified byte order into wstring up to but not including \U0000.
 */
void sbuf_t::getUTF16(size_t i, byte_order_t bo, std::wstring &utf16_string) const {
    // clear any residual value
    utf16_string = std::wstring();

    // read the code units
    size_t offset;
    for (offset=i; offset<bufsize-1; offset += 2) {
        uint16_t code_unit = get16u(offset, bo);
        //cout << "sbuf.cpp getUTF16 i: " << i << " code unit: " << code_unit << "\n";

        // stop before \U0000
        if (code_unit == 0) {
            // at \U0000
            break;
        }

        // accept the code unit
        utf16_string.push_back(code_unit);
    }
}

