/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * sbuf.h:
 *
 * sbuf ("safer buffer") provides a typesafe means to
 * refer to binary data within the context of a C++ computer forensics
 * tool. The sbuf is a const buffer for which the first byte's
 * position is tracked in the "pos0" variable (the position of
 * byte[0]). The buffer may come from a disk, a disk image, or be the
 * result of decompressing or otherwise decoding other data.
 *
 * Created and maintained by Simson Garfinkel, 2007--2012.
 *
 * sbuf_stream is a stream-oriented interface for reading sbuf data. 
 */
 

#ifndef SBUF_H
#define SBUF_H

#ifdef HAVE_STRING_H
#include <string.h>
#endif

//Don't turn this on; it currently makes scan_net crash.
//#define SBUF_TRACK

/* required per C++ standard */
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <string>
#include <sstream>
#include <iostream>


/****************************************************************
 *** pos0_t
 ****************************************************************/

/** \addtogroup bulk_extractor_APIs
 * @{
 */
/** \file */
/**
 * \class pos0_t
 * The pos0_t structure is used to record the forensic path of the
 * first byte of an sbuf. The forensic path can include strings associated
 * with decompressors and ordinals associated with offsets.
 * 
 * e.g., 1000-GZIP-300-BASE64-30 means go 1000 bytes into the stream,
 *       unzip, go 300 bytes into the decompressed stream, un-BASE64, and
 *       go 30 bytes into that.
 * 
 * pos0_t uses a string to hold the base path and the offset into that path
 * in a 64-bit number.  
 */

inline int64_t stoi64(std::string str)
{
    int64_t val(0);
    std::istringstream ss(str);
    ss >> val;
    return val;
}

class pos0_t {
public:
    const std::string path;                     /* forensic path of decoders*/
    const uint64_t    offset;                   /* location of buf[0] */
    
    explicit pos0_t():path(""),offset(0){}
    pos0_t(std::string s):path(s),offset(0){}
    pos0_t(std::string s,uint64_t o):path(s),offset(o){}
    pos0_t(const pos0_t &obj):path(obj.path),offset(obj.offset){ }
    std::string str() const {           // convert to a string, with offset included
        std::stringstream ss;
        if(path.size()>0){
            ss << path << "-";
        }
        ss << offset;
        return ss.str();
    }
    bool isRecursive() const {          // is there a path?
        return path.size() > 0;
    } 
    std::string firstPart() const {     // the first part of the path
        size_t p = path.find('-');
        if(p==std::string::npos) return std::string("");
        return path.substr(0,p);
    }
    std::string lastAddedPart() const { // the last part of the path, before the offset
        size_t p = path.rfind('-');
        if(p==std::string::npos) return std::string("");
        return path.substr(p+1);
    }
    std::string alphaPart() const {    // return the non-numeric parts, with /'s between each
        std::string desc;
        bool inalpha = false;
        /* Now get the std::string part of pos0 */
        for(std::string::const_iterator it = path.begin();it!=path.end();it++){
            if((*it)=='-'){
                if(desc.size()>0 && desc.at(desc.size()-1)!='/') desc += '/';
                inalpha=false;
            }
            if(isalpha(*it) || (inalpha && isdigit(*it))){
                desc += *it;
                inalpha=true;
            }
        }
        return desc;
    }
    uint64_t imageOffset() const {      // return the offset from start of disk
        if(path.size()>0) return stoi64(path);
        return offset;
    }


    /**
     * Return a new position that's been shifted by an offset
     */
    pos0_t shift(int64_t s) const {
        if(s==0) return *this;
        size_t p = path.find('-');
        if(p==std::string::npos){            // no path
            return pos0_t("",offset+s);
        }
        /* Figure out the value of the shift */
        int64_t baseOffset = stoi64(path.substr(0,p-1));
        std::stringstream ss;
        ss << (baseOffset+s) << path.substr(p);
        return pos0_t(ss.str(),offset);
    }
};

/** iostream support for the pos0_t */
inline std::ostream & operator <<(std::ostream &os,const class pos0_t &pos0) {
    os << "(" << pos0.path << "|" << pos0.offset << ")";
    return os;
}


/** Append a string (subdir).
 * The current offset is a prefix to the subdir.
 */
inline class pos0_t operator +(pos0_t pos,const std::string &subdir) {
    std::stringstream ss;
    ss << pos.path << (pos.path.size()>0 ? "-" : "") << pos.offset << "-" << subdir;
    return pos0_t(ss.str(),0);
};

/** Adding an offset */
inline class pos0_t operator +(pos0_t pos,int64_t delta) {
    return pos0_t(pos.path,pos.offset+delta);
};

/** \name Comparision operations
 * @{
 */
inline bool operator <(const class pos0_t &pos0,const class pos0_t & pos1)  {
    if(pos0.path.size()==0 && pos1.path.size()==0) return pos0.offset < pos1.offset;
    if(pos0.path == pos1.path) return pos0.offset < pos1.offset;
    return pos0.path < pos1.path;
};

inline bool operator >(const class pos0_t & pos0,const class pos0_t &pos1)  {
    if(pos0.path.size()==0 && pos1.path.size()==0) return pos0.offset > pos1.offset;
    if(pos0.path == pos1.path) return pos0.offset > pos1.offset;
    return pos0.path > pos1.path;
};

inline bool operator ==(const class pos0_t & pos0,const class pos0_t &pos1) {
    return pos0.path==pos1.path && pos0.offset==pos1.offset;
};
/** @} */

/**
 * \class managed_malloc Like new[], but it automatically gets freed when the object is dropped.
 * throws std::bad_alloc if no memory.
 */
template < class TYPE > class managed_malloc {
    // default construction, copy construction and assignment are meaningless
    // and not implemented
    managed_malloc& operator=(const managed_malloc&); 
    managed_malloc(const managed_malloc&);
    managed_malloc();
public:
    TYPE *buf;
    managed_malloc(size_t bytes):buf(new TYPE[bytes]){ }
    ~managed_malloc(){
        if(buf) delete []buf;
    }
};


/**
 * \class sbuf_t
 * This class describes the search buffer.
 * The accessors are safe so that no buffer overflow can happen.
 * Integer readers may throw sbuf_bounds_exception.
 *
 * This structure actually holds the data.
 * We use a pos0_t to maintain the address of the first byte.
 *
 * There are lots of ways for allocating an sbuf_t:
 * - map from a file.
 * - set from a block of memory.
 * - a subset of an existing sbuf_t (sbuf+10 gives you 10 bytes in, and therefore 10 bytes shorter)
 *
 * The subf_t class remembers how the sbuf_t was allocated and
 * automatically frees whatever resources are needed when it is freed.
 *
 * \warning DANGER: You must delete sbuf_t structures First-In,
 * Last-out, otherwise bad things can happen. (For example, if you
 * make a subset sbuf_t from a mapped file and unmap the file, the
 * subset will now point to unallocated memory.)
 */
class sbuf_t {
private:
    /* The private structures keep track of memory management */
    int    fd;                          /* file this came from if mmapped file */
public:;
    bool   should_unmap;                /* munmap buffer when done */
    bool   should_free;                 /* should buf be freed when this sbuf is deleted? */
    bool   should_close;                /* close(fd) when done. */
    static size_t min(size_t a,size_t b){
        return a<b ? a : b;
    }

public:
    int     page_number;                /* used for debugging */
    pos0_t  pos0;                       /* the path of buf[0] */
private:
    const sbuf_t  *parent;              // parent sbuf references data in another.
public:
    mutable int   children;             // number of child sbufs; can get increment in copy
public:
    //private:               // one day
    /**
     * \deprecated
     * This field will be private in a future release of \b bulk_extractor.
     */
    const uint8_t *buf;         /* start of the buffer */
public:
     size_t  bufsize;           /* size of the buffer */
     size_t  pagesize;          /* page data; the rest is the 'margin'. pagesize <= bufsize */
    
private:
    void release();                     // release allocated storage
    // default assignment not implemented
    sbuf_t &operator=(const sbuf_t &that);
public:
    /** Make an empty sbuf.
        It's used for situations where an sbuf is needed but not referenced */
    explicit sbuf_t():fd(0),should_unmap(false),should_free(false),should_close(false),
             page_number(0),pos0(),
             parent(0),
             children(0),buf(0),bufsize(0),pagesize(0){
    }

    /****************************************************************
     *** Child allocators --- allocate an sbuf from another sbuf
     ****************************************************************/

    /**
     * Make an sbuf from a parent. 
     * note: don't add an 'explicit' --- it causes problems.
     */
    sbuf_t(const sbuf_t &that):
             fd(0),should_unmap(false),should_free(false),should_close(false),
             page_number(that.page_number),pos0(that.pos0),
             parent(that.highest_parent()),
             children(0),buf(that.buf),bufsize(that.bufsize),pagesize(that.pagesize){
        parent->add_child(*this);
    }

    /**
     * Make an sbuf from a parent but with a different path. 
     */
    explicit sbuf_t(const pos0_t &that_pos0, const sbuf_t &that_sbuf ):
        fd(0),should_unmap(false),should_free(false),should_close(false),
        page_number(that_sbuf.page_number),pos0(that_pos0),
        parent(that_sbuf.highest_parent()),children(0),
        buf(that_sbuf.buf),bufsize(that_sbuf.bufsize),pagesize(that_sbuf.pagesize){
        parent->add_child(*this);
    }

    /**
     * make an sbuf from a parent but with an indent.
     */
    sbuf_t(const sbuf_t &that_sbuf,size_t off):
        fd(0),should_unmap(false),should_free(false),should_close(false),
        page_number(that_sbuf.page_number),pos0(that_sbuf.pos0+off),
        parent(that_sbuf.highest_parent()),children(0),
        buf(that_sbuf.buf+off),
        bufsize(that_sbuf.bufsize > off ? that_sbuf.bufsize-off : 0),
        pagesize(that_sbuf.pagesize > off ? that_sbuf.pagesize-off : 0){
    }

    /** Allocate from an existing sbuf.
     * The allocated buf MUST be freed before the source, since no copy is made...
     */
    explicit sbuf_t(const sbuf_t &sbuf,size_t off,size_t len):
        fd(0), should_unmap(false), should_free(false), should_close(false),
        page_number(sbuf.page_number),pos0(sbuf.pos0+off),
        parent(sbuf.highest_parent()),
        children(0), buf(sbuf.buf+off),
        bufsize(off+len<sbuf.bufsize ? len : sbuf.bufsize-off),
        pagesize(off+len<sbuf.bufsize ? len : sbuf.bufsize-off){
        parent->add_child(*this);
    };

    /****************************************************************
     *** Allocators that allocate from memory
     ****************************************************************/

    /* Allocators */
    /** Allocate a new buffer of a given size for filling.
     * This is the one case where buf is written into...
     * This should probably be a subclass mutable_sbuf_t() for clarity.
     */

    /* Allocate from an existing buffer, optionally freeing that buffer */
    explicit sbuf_t(const pos0_t &pos0_,const uint8_t *buf_,
                    size_t bufsize_,size_t pagesize_,
                    int fd_, bool should_unmap_,bool should_free_,bool should_close_):
        fd(fd_), should_unmap(should_unmap_), should_free(should_free_),
        should_close(should_close_),
        page_number(0),pos0(pos0_),parent(0),children(0),buf(buf_),bufsize(bufsize_),
        pagesize(min(pagesize_,bufsize_)){
    };

    /* Similar to above, but with no fd */
    explicit sbuf_t(const pos0_t &pos0_,const uint8_t *buf_,
                    size_t bufsize_,size_t pagesize_,bool should_free_):
        fd(0), should_unmap(false), should_free(should_free_), should_close(false),
        page_number(0),pos0(pos0_),parent(0),children(0),buf(buf_),bufsize(bufsize_),
        pagesize(min(pagesize_,bufsize_)){
    };

    /**
     * the + operator returns a new sbuf that is i bytes in and, therefore, i bytes smaller.
     * Note:
     * 1. We assume that pagesize is always smaller than or equal to bufsize.
     * 2. The child sbuf uses the parent's memory. If the parent gets deleted, the child points
     *    to invalid data.
     *
     * 3. If i is bigger than pagesize, then an sbuf is returned with
     *    0 bytes in the page and all of the margin.
     *
     *    (Because we won't return what's in the margin as page data.)
     */
    sbuf_t operator +(size_t off ) const {
        return sbuf_t(*this,off);
    }

    virtual ~sbuf_t(){
#if defined(SBUF_TRACK) && defined(HAVE___SYNC_ADD_AND_FETCH)
        assert(__sync_fetch_and_add(&children,0)==0);
#endif
        if(parent) parent->del_child(*this);
        release();
    }

    /* Allocate a sbuf from a file mapped into memory */
    static sbuf_t *map_file(const std::string &fname); 
    static sbuf_t *map_file(const std::string &fname,int fd); // if file is already opened
    static const std::string U10001C;         // default delimeter character in bulk_extractor
    static std::string map_file_delimiter; // character placed
    static void set_map_file_delimiter(const std::string &new_delim){
        map_file_delimiter = new_delim;
    }

    /* Properties */
    size_t size() const {return bufsize;} // return the number of bytes
    size_t left(size_t n) const {return n<bufsize ? bufsize-n : 0;}; // how much space is left at n

    const sbuf_t *highest_parent() const; // returns the parent of the parent...
    void add_child(const sbuf_t &child) const {
#if defined(HAVE___SYNC_ADD_AND_FETCH) && defined(SBUF_TRACK)
        __sync_fetch_and_add(&children,1);
        std::cerr << "add_child(" << this << ")="<<children << "\n";
#endif
    }
    void del_child(const sbuf_t &child) const {
#if defined(HAVE___SYNC_ADD_AND_FETCH) && defined(SBUF_TRACK)
        __sync_fetch_and_add(&children,-1);
        std::cerr << "del_child(" << this << ")="<<children << "\n";
        assert(__sync_fetch_and_add(&children,0)>=0);
#endif
    }

    /** Find the offset of a byte */
    size_t offset(const uint8_t *loc) const {
        if(loc<buf) return 0;
        if(loc>buf+bufsize) return bufsize;
        return loc-buf;
    }

    /**
     * asString - returns the sbuf as a string
     */

    std::string asString() const {return std::string((reinterpret_cast<const char *>(buf)),bufsize);}

    /****************************************************************
     *** range_exception_t
     *** An sbuf_range_exception object is thrown if the attempted sbuf access is out of range.
     ****************************************************************/
    /**
     * sbuf_t raises an sbuf_range_exception when an attempt is made to read past the end of buf.
     */
    class range_exception_t: public std::exception {
    public:
        virtual const char *what() const throw() {
            return "Error: Read past end of sbuf";
        }
    };

    /****************************************************************
     *** The following get functions read integer and string types
     *** or else throw an sbuf_range_exception if out of range.
     ****************************************************************/

    /* Search functions --- memcmp at a particular location */
    int memcmp(const uint8_t *cbuf,size_t at,size_t len) const;

    /**
     * \name unsigned int Intel (littel-endian) readers
     * @{
     * these get functions safely return an unsigned integer value for the offset of i,
     * in Intel (little-endian) byte order or else throw sbuf_range_exception if out of range.
     */
    uint8_t  get8u(size_t i) const;
    uint16_t get16u(size_t i) const;
    uint32_t get32u(size_t i) const;
    uint64_t get64u(size_t i) const;
    /** @} */

    /**
     * \name unsigned int Motorola (big-endian) readers
     * @{
     * these get functions safely return an unsigned integer value for the offset of i,
     * in Motorola (big-endian) byte order or else throw sbuf_range_exception if out of range.
     */
    uint8_t  get8uBE(size_t i) const;
    uint16_t get16uBE(size_t i) const;
    uint32_t get32uBE(size_t i) const;
    uint64_t get64uBE(size_t i) const;
    /** @} */

    /**
     * \name signed int Intel (little-endian) readers
     * @{
     * these get functions safely return a signed integer value for the offset of i,
     * in Intel (little-endian) byte order or else throw sbuf_range_exception if out of range.
     */
    int8_t  get8i(size_t i) const;
    int16_t get16i(size_t i) const;
    int32_t get32i(size_t i) const;
    int64_t get64i(size_t i) const;
    /** @} */

    /**
     * \name signed int Motorola (big-endian) readers
     * @{
     * these get functions safely return a signed integer value for the offset of i,
     * in Motorola (big-endian) byte order or else throw sbuf_range_exception if out of range.
     */
    int8_t  get8iBE(size_t i) const;
    int16_t get16iBE(size_t i) const;
    int32_t get32iBE(size_t i) const;
    int64_t get64iBE(size_t i) const;
    /** @} */

    /**
     * some get functions take byte_order_t as a specifier to indicate which endian format to use.
     */
    typedef enum {BO_LITTLE_ENDIAN=0,BO_BIG_ENDIAN=1} byte_order_t;

    /**
     * \name unsigned int, byte-order specified readers
     * @{
     * these get functions safely return an unsigned integer value for the offset of i,
     * in the byte order of your choice or else throw sbuf_range_exception if out of range.
     */
    uint8_t  get8u(size_t i,byte_order_t bo) const;
    uint16_t get16u(size_t i,byte_order_t bo) const;
    uint32_t get32u(size_t i,byte_order_t bo) const;
    uint64_t get64u(size_t i,byte_order_t bo) const;
    /** @} */

    /**
     * \name signed int, byte-order specified readers
     * @{
     * these get functions safely return a signed integer value for the offset of i,
     * in the byte order of your choice or else throw sbuf_range_exception if out of range.
     */
    int8_t  get8i(size_t i,byte_order_t bo) const;
    int16_t get16i(size_t i,byte_order_t bo) const;
    int32_t get32i(size_t i,byte_order_t bo) const;
    int64_t get64i(size_t i,byte_order_t bo) const;
    /** @} */

    /**
     * \name string readers
     * @{
     * These get functions safely read string
     */
    void getUTF8(size_t i, size_t num_octets_requested, std::string &utf8_string) const;
    void getUTF8(size_t i, std::string &utf8_string) const;
    /** @} */

    /**
     * \name wstring readers
     * @{
     * These get functions safely read wstring
     */
    void getUTF16(size_t i, size_t num_code_units_requested, std::wstring &utf16_string) const;
    void getUTF16(size_t i, std::wstring &utf16_string) const;
    void getUTF16(size_t i, size_t num_code_units_requested, byte_order_t bo, std::wstring &utf16_string) const;
    void getUTF16(size_t i, byte_order_t bo, std::wstring &utf16_string) const;
    /** @} */

    /**
     * The [] operator safely returns what's at index [i] or else returns 0 if out of range.
     * We made a decision that this would not throw the exception
     * Notice that we don't need to check to see if i<0 because i is unsigned.
     */
    uint8_t operator [](size_t i) const {
        return (i<bufsize) ? buf[i] : 0;
    }

    /**
     * Find the next occurance of a character in the buffer
     * starting at a given point.
     * return -1 if there is none to find.
     */
    ssize_t find(uint8_t ch,size_t start) const {
        for(;start<pagesize;start++){
            if(buf[start]==ch) return start;
        }
        return -1;
    }

    /**
     * Find the next occurance of a char* string in the buffer
     * starting at a give point.
     * Return offset or -1 if there is none to find.
     * This would benefit from a boyer-Moore implementation
     */
    ssize_t find(const char *str,size_t start) const {
        if(str[0]==0) return -1;        // nothing to search for

        for(;start<pagesize;start++){
            const uint8_t *p = (const uint8_t *)memchr(buf+start,str[0],bufsize-start);
            if(p==0) return -1;             // first character not present,
            size_t loc = p-buf;
            for(size_t i=0;loc + i < bufsize && str[i];i++){
                if(buf[loc+i] != str[i]) break;
                if(str[i+1]==0) return loc; // next char is null, so we are found!
            }
            start = loc+1;              // advance to character after found character
        }
        return -1;
    }

    std::string substr(size_t loc,size_t len) const; /* make a substring */
    bool is_constant(size_t loc,size_t len,uint8_t ch) const; // verify that it's constant
    bool is_constant(uint8_t ch) const { return is_constant(0,this->pagesize,ch); }

    // Return a pointer to a structure contained within the sbuf if there is
    // room, otherwise return a null pointer.
    template<class TYPE>
    const TYPE * get_struct_ptr(uint32_t pos) const {
        if (pos + sizeof(TYPE) <= bufsize) {
            return reinterpret_cast<const TYPE *> (buf+pos);
        }
        return NULL;
    }
    

    /**
     * These are largely for debugging, but they also support the BEViewer.
     * Dump the sbuf to a stream.
     */
    void raw_dump(std::ostream &os,uint64_t start,uint64_t len) const;
    void raw_dump(int fd,uint64_t start,uint64_t len) const; // writes to a raw file descriptor
    void hex_dump(std::ostream &os,uint64_t start,uint64_t len) const;
    void hex_dump(std::ostream &os) const; /* dump all */
    ssize_t  write(int fd,size_t loc,size_t len) const; /* write to a file descriptor, returns # bytes written */
    ssize_t  write(FILE *f,size_t loc,size_t len) const; /* write to a file descriptor, returns # bytes written */
};

std::ostream & operator <<(std::ostream &os,const sbuf_t &sbuf);

#include "sbuf_private.h"

#endif
