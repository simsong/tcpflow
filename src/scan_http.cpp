/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/**
 *
 * scan_http:
 * Decodes HTTP responses
 */

#include "config.h"

#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"

#include "http-parser/http_parser.h"

#include "mime_map.h"

#ifdef HAVE_LIBZ
#  define ZLIB_CONST
#  ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#    pragma GCC diagnostic ignored "-Wundef"
#    pragma GCC diagnostic ignored "-Wcast-qual"
#  endif
#  ifdef HAVE_ZLIB_H
#    include <zlib.h>
#  endif
#else
#  define z_stream void *               // prevents z_stream from generating an error
#endif

#define MIN_HTTP_BUFSIZE 80             // don't bother parsing smaller than this

#include <sys/types.h>
#include <iostream>
#include <algorithm>
#include <map>
#include <iomanip>

#define HTTP_CMD "http_cmd"
std::string http_cmd;                   // command to run on each http object


/* define a callback object for sharing state between scan_http() and its callbacks
 */
class scan_http_cbo {
private:
    typedef enum {NOTHING,FIELD,VALUE} last_on_header_t;
    class not_impl: public std::exception {
	virtual const char *what() const throw() { return "copying tcpip objects is not implemented."; }
    };

    scan_http_cbo(const scan_http_cbo& c) __attribute__ ((__noreturn__)):
    path(c.path), base(c.base), xmlstream(c.xmlstream),xml_fo(),request_no(c.request_no),
        headers(c.headers), last_on_header(c.last_on_header), header_value(c.header_value), header_field(c.header_field),
        output_path(c.output_path), fd(c.fd), first_body(c.first_body),bytes_written(c.bytes_written),unzip(c.unzip), 
        zs(), zinit(false), zfail(false) {throw new not_impl();};

    scan_http_cbo &operator=(const scan_http_cbo &c) {throw new not_impl();}

public:
    virtual ~scan_http_cbo(){
        on_message_complete();          // make sure message was ended
    }
    scan_http_cbo(const std::string& path_,const char *base_,std::stringstream *xmlstream_) :
        path(path_), base(base_),xmlstream(xmlstream_),xml_fo(),request_no(0),
        headers(), last_on_header(NOTHING), header_value(), header_field(),
        output_path(), fd(-1), first_body(true),bytes_written(0),unzip(false),zs(),zinit(false),zfail(false){};
private:        
        
    const std::string path;             // where data gets written
    const char *base;                   // where data started in memory
    std::stringstream *xmlstream;       // if present, where to put the fileobject annotations
    std::stringstream xml_fo;           // xml stream for this file object
    int request_no;                     // request number
        
    /* parsed headers */
    std::map<std::string, std::string> headers;
        
    /* placeholders for possibly-incomplete header data */
    last_on_header_t last_on_header;
    std::string header_value, header_field;
    std::string output_path;
    int         fd;                         // fd for writing
    bool        first_body;
    uint64_t    bytes_written;

    /* decompression for gzip-encoded streams. */
    bool     unzip;           // should we be decompressing?
    z_stream zs;              // zstream (avoids casting and memory allocation)
    bool     zinit;           // we have initialized the zstream 
    bool     zfail;           // zstream failed in some manner, so ignore the rest of this stream

    /* The static functions are callbacks; they wrap the method calls */
#define CBO (reinterpret_cast<scan_http_cbo*>(parser->data))
public:
    static int scan_http_cb_on_message_begin(http_parser * parser) { return CBO->on_message_begin();}
    static int scan_http_cb_on_url(http_parser * parser, const char *at, size_t length) { return 0;}
    static int scan_http_cb_on_header_field(http_parser * parser, const char *at, size_t length) { return CBO->on_header_field(at,length);}
    static int scan_http_cb_on_header_value(http_parser * parser, const char *at, size_t length) { return CBO->on_header_value(at,length); }
    static int scan_http_cb_on_headers_complete(http_parser * parser) { return CBO->on_headers_complete();}
    static int scan_http_cb_on_body(http_parser * parser, const char *at, size_t length) { return CBO->on_body(at,length);}
    static int scan_http_cb_on_message_complete(http_parser * parser) {return CBO->on_message_complete();}
#undef CBO
private:
    int on_message_begin();
    int on_url(const char *at, size_t length);
    int on_header_field(const char *at, size_t length);
    int on_header_value(const char *at, size_t length);
    int on_headers_complete();
    int on_body(const char *at, size_t length);
    int on_message_complete();          
};
    

/**
 * on_message_begin:
 * Increment request nubmer. Note that the first request is request_no = 1
 */

int scan_http_cbo::on_message_begin()
{
    request_no ++;
    return 0;
}

/**
 * on_url currently not implemented.
 */

int scan_http_cbo::on_url(const char *at, size_t length)
{
    return 0;
}


/* Note 1: The state machine is defined in http-parser/README.md
 * Note 2: All header field names are converted to lowercase.
 *         This is consistent with the RFC.
 */

int scan_http_cbo::on_header_field(const char *at,size_t length)
{
    std::string field(at,length);
    std::transform(field.begin(), field.end(), field.begin(), ::tolower);
    
    switch(last_on_header){
    case NOTHING:                       
        // Allocate new buffer and copy callback data into it
        header_field = field;
        break;
    case VALUE:
        // New header started.
        // Copy current name,value buffers to headers
        // list and allocate new buffer for new name
        headers[header_field] = header_value;
        header_field = field;
        break;
    case FIELD:
        // Previous name continues. Reallocate name
        // buffer and append callback data to it
        header_field.append(field);
        break;
    }
    last_on_header = FIELD;
    return 0;
}

int scan_http_cbo::on_header_value(const char *at, size_t length)
{
    const std::string value(at,length);
    switch(last_on_header){
    case FIELD:
        //Value for current header started. Allocate
        //new buffer and copy callback data to it
        header_value = value;
        break;
    case VALUE:
        //Value continues. Reallocate value buffer
        //and append callback data to it
        header_value.append(value);
        break;
    case NOTHING:
        // this shouldn't happen
        DEBUG(10)("Internal error in http-parser");
        break;
    }
    last_on_header = VALUE;

    return 0;
}

/**
 * called when last header is read.
 * Determine the filename based on request_no and extension.
 * Also see if decompressing is happening...
 */

int scan_http_cbo::on_headers_complete()
{
    tcpdemux *demux = tcpdemux::getInstance();

    /* Add the most recently read header to the map, if any */
    if (last_on_header==VALUE) {
        headers[header_field] = header_value;
        header_field="";
    }
        
    /* Set output path to <path>-HTTPBODY-nnn.ext for each part.
     * This is not consistent with tcpflow <= 1.3.0, which supported only one HTTPBODY,
     * but it's correct...
     */
    
    std::stringstream os;
    os << path << "-HTTPBODY-" << std::setw(3) << std::setfill('0') << request_no << std::setw(0);

    /* See if we can guess a file extension */
    std::string extension = get_extension_for_mime_type(headers["content-type"]);
    if (extension.size()) {
        os << "." << extension;
    }
        
    output_path = os.str();
        
    /* Choose an output function based on the content encoding */
    std::string content_encoding(headers["content-encoding"]);

    if ((content_encoding == "gzip" || content_encoding == "deflate") && (demux->opt.gzip_decompress)){
#ifdef HAVE_LIBZ
        DEBUG(10) ( "%s: detected zlib content, decompressing", output_path.c_str());
        unzip = true;
#else
        /* We can't decompress, so just give it a .gz */
        output_path.append(".gz");
        DEBUG(5) ( "%s: refusing to decompress since zlib is unavailable", output_path.c_str() );
#endif
    } 
        
    /* Open the output path */
    fd = demux->retrying_open(output_path.c_str(), O_WRONLY|O_CREAT|O_BINARY|O_TRUNC, 0644);
    if (fd < 0) {
        DEBUG(1) ("unable to open HTTP body file %s", output_path.c_str());
    }

    first_body = true;                  // next call to on_body will be the first one
        
    /* We can do something smart with the headers here.
     *
     * For example, we could:
     *  - Record all headers into the report.xml
     *  - Pick the intended filename if we see Content-Disposition: attachment; name="..."
     *  - Record headers into filesystem extended attributes on the body file
     */
    return 0;
}

/* Write to fd, optionally decompressing as we go */
int scan_http_cbo::on_body(const char *at,size_t length)
{
    if (fd < 0)    return -1;              // no open fd? (internal error)x
    if (length==0) return 0;               // nothing to write

    if(first_body){                      // stuff for first time on_body is called
        xml_fo << "     <byte_run file_offset='" << (at-base) << "'><fileobject><filename>" << output_path << "</filename>";
        first_body = false;
    }

    /* If not decompressing, just write the data and return. */
    if(unzip==false){
        int rv = write(fd,at,length);
        if(rv<0) return -1;             // write error; that's bad
        bytes_written += rv;
        return 0;
    }

#ifndef HAVE_LIBZ
    assert(0);                          // shoudln't have gotten here
#endif    
    if(zfail) return 0;                 // stream was corrupt; ignore rest
    /* set up this round of decompression, using a small local buffer */

    /* Call init if we are not initialized */
    char decompressed[65536];           // where decompressed data goes
    if (!zinit) {
        memset(&zs,0,sizeof(zs));
        zs.next_in = (Bytef*)at;
        zs.avail_in = length;
        zs.next_out = (Bytef*)decompressed;
        zs.avail_out = sizeof(decompressed);
        
        int rv = inflateInit2(&zs, 32 + MAX_WBITS);      /* 32 auto-detects gzip or deflate */
        if (rv != Z_OK) {
            /* fail! */
            DEBUG(3) ("decompression failed at stream initialization; rv=%d bad Content-Encoding?",rv);
            zfail = true;
            return 0;
        }
        zinit = true;                   // successfully initted
    } else {
        zs.next_in = (Bytef*)at;
        zs.avail_in = length;
        zs.next_out = (Bytef*)decompressed;
        zs.avail_out = sizeof(decompressed);
    }
        
    /* iteratively decompress, writing each time */
    while (zs.avail_in > 0) {
        /* decompress as much as possible */
        int rv = inflate(&zs, Z_SYNC_FLUSH);
                
        if (rv == Z_STREAM_END) {
            /* are we done with the stream? */
            if (zs.avail_in > 0) {
                /* ...no. */
                DEBUG(3) ("decompression completed, but with trailing garbage");
                return 0;
            }
        } else if (rv != Z_OK) {
            /* some other error */
            DEBUG(3) ("decompression failed (corrupted stream?)");
            zfail = true;               // ignore the rest of this stream
            return 0;
        }
                
        /* successful decompression, at least partly */
        /* write the result */
        int bytes_decompressed = sizeof(decompressed) - zs.avail_out;
        ssize_t written = write(fd, decompressed, bytes_decompressed);

        if (written < bytes_decompressed) {
            DEBUG(3) ("writing decompressed data failed");
            zfail= true;
            return 0;
        }
        bytes_written += written;
                
        /* reset the buffer for the next iteration */
        zs.next_out = (Bytef*)decompressed;
        zs.avail_out = sizeof(decompressed);
    }
    return 0;
}


/**
 * called at the conclusion of each HTTP body.
 * Clean out all of the state for this HTTP header/body pair.
 */

int scan_http_cbo::on_message_complete()
{
    /* Close the file */
    headers.clear();
    header_field = "";
    header_value = "";
    last_on_header = NOTHING;
    if(fd >= 0) {
        if (::close(fd) != 0) {
            perror("close() of http body");
        }
        fd = -1;
    }

    /* Erase zero-length files and update the DFXML */
    if(bytes_written>0){
        /* Update DFXML */
        if(xmlstream){
            xml_fo << "<filesize>" << bytes_written << "</filesize></fileobject></byte_run>\n";
            if(xmlstream) *xmlstream << xml_fo.str();
        }
        if(http_cmd.size()>0){
            std::string cmd = http_cmd + " " + output_path;
            system(cmd.c_str());
        }
    } else {
        /* Nothing written; erase the file */
        if(output_path.size() > 0){
            //std::cerr << "unlink " << output_path << "\n";
            ::unlink(output_path.c_str());
        }
    }

    /* Erase the state variables for this part */
    xml_fo.str() = "";
    output_path = "";
    bytes_written=0;
    unzip = false;
    if(zinit){
        inflateEnd(&zs);
        zinit = false;
    }
    zfail = false;
    return 0;
}


/***
 * the HTTP scanner plugin itself
 */

extern "C"
void  scan_http(const class scanner_params &sp,const recursion_control_block &rcb)
{
    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
        std::cerr << "scan_http requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
                  << "got version " << sp.sp_version << "\n";
        exit(1);
    }

    if(sp.phase==scanner_params::startup){
        sp.info->name  = "http";
        sp.info->flags = scanner_info::SCANNER_DISABLED; // default disabled
        http_cmd = be_config[HTTP_CMD];
        return;         /* No feature files created */
    }

    if(sp.phase==scanner_params::scan){
        /* See if there is an HTTP response */
        if(sp.sbuf.bufsize>=MIN_HTTP_BUFSIZE && sp.sbuf.memcmp(reinterpret_cast<const uint8_t *>("HTTP/1."),0,7)==0){
            /* Smells enough like HTTP to try parsing */
            /* Set up callbacks */
            http_parser_settings scan_http_parser_settings;
            scan_http_parser_settings.on_message_begin          = scan_http_cbo::scan_http_cb_on_message_begin;
            scan_http_parser_settings.on_url                    = scan_http_cbo::scan_http_cb_on_url;
            scan_http_parser_settings.on_header_field           = scan_http_cbo::scan_http_cb_on_header_field;
            scan_http_parser_settings.on_header_value           = scan_http_cbo::scan_http_cb_on_header_value;
            scan_http_parser_settings.on_headers_complete       = scan_http_cbo::scan_http_cb_on_headers_complete;
            scan_http_parser_settings.on_body                   = scan_http_cbo::scan_http_cb_on_body;
            scan_http_parser_settings.on_message_complete       = scan_http_cbo::scan_http_cb_on_message_complete;
                        
            if(sp.sbufxml) (*sp.sbufxml) << "\n    <byte_runs>\n";
            for(size_t offset=0;;){
                /* Set up a parser instance for the next chunk of HTTP responses and data.
                 * This might be repeated several times due to connection re-use and multiple requests.
                 * Note that the parser is not a C++ library but it can pass a "data" to the
                 * callback. We put the address for the scan_http_cbo object in the data and
                 * recover it with a cast in each of the callbacks.
                 */
                
                /* Make an sbuf for the remaining data.
                 * Note that this may not be necessary, because in our test runs the parser
                 * processed all of the data the first time through...
                 */
                sbuf_t sub_buf(sp.sbuf, offset);
                                
                const char *base = reinterpret_cast<const char*>(sub_buf.buf);
                http_parser parser;
                http_parser_init(&parser, HTTP_RESPONSE);

                scan_http_cbo cbo(sp.sbuf.pos0.path,base,sp.sbufxml);
                parser.data = &cbo;

                /* Parse */
                size_t parsed = http_parser_execute(&parser, &scan_http_parser_settings,
                                                    base, sub_buf.size());
                assert(parsed <= sub_buf.size());
                                
                /* Indicate EOF (flushing callbacks) and terminate if we parsed the entire buffer.
                 */
                if (parsed == sub_buf.size()) {
                    http_parser_execute(&parser, &scan_http_parser_settings, NULL, 0);
                    break;
                }
                                
                /* Stop parsing if we parsed nothing, as that indicates something header! */
                if (parsed == 0) {
                    break;
                }
                                
                /* Stop parsing if we're a connection upgrade (e.g. WebSockets) */
                if (parser.upgrade) {
                    DEBUG(9) ("upgrade connection detected (WebSockets?); cowardly refusing to dump further");
                    break;
                }
                                
                /* Bump the offset for next iteration */
                offset += parsed;
            }
            if(sp.sbufxml) (*sp.sbufxml) << "    </byte_runs>";
        }
    }
}
