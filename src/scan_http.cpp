/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/**
 *
 * scan_http:
 * Decodes HTTP responses
 */

#include "config.h"
#include "tcpflow.h"
#include <iostream>
#include <map>
#include <sys/types.h>
#include "bulk_extractor_i.h"

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


/***
 * data structures
 */

//typedef struct scan_http_data_t;
//typedef int(*write_data_fn_t)(scan_http_data_t * data, sbuf_t& buf);

/* define a callback object for sharing state between scan_http() and its callbacks
 */
class scan_http_cbo {
private:
    scan_http_cbo(const scan_http_cbo& c) :
        path(c.path), sbuf(c.sbuf), request_no(c.request_no),
        headers(c.headers), header_state(c.header_state), header_value(c.header_value), header_field(c.header_field),
        output_path(c.output_path), fd(c.fd), decompress_on_write(c.decompress_on_write), bytes_written(c.bytes_written), zs(), zinit(false){};
public:
    virtual ~scan_http_cbo(){
        if(fd!=-1 || zinit) close();    // clean up if we are not clean
    }
    scan_http_cbo(const std::string& path_, const sbuf_t &sbuf_) :
        path(path_), sbuf(sbuf_), request_no(0),
        headers(), header_state(0), header_value(), header_field(),
        output_path(), fd(-1), decompress_on_write(false),bytes_written(0),zs(),zinit(false){};
private:        
        
    const std::string path;             // where data gets written
    const sbuf_t &sbuf;                 // sbuf holding the data
    int request_no;                     // request number
        
    /* parsed headers */
    std::map<std::string, std::string> headers;
        
    /* placeholders for possibly-incomplete header data */
    int header_state;                   // 0, 1 or 2 
    std::string header_value, header_field;
    std::string output_path;
        
    int fd;                             // fd for writing
    bool decompress_on_write;           // should we be decompressing?
    uint64_t bytes_written;
    z_stream zs;                       // zstream (avoids casting and memory allocation)
    bool zinit;                         // we have initialized the zstream 
    
    //write_data_fn_t write_fn;
    //void * write_fn_state;
        
    void close();

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
    
/*
 * close the file descriptor and kill the decompressor if it is present
 */
void scan_http_cbo::close()
{
    if(fd >= 0) {
        if (::close(fd) != 0) {
            perror("close() of http body");
        }
        fd = -1;
    }

    if(decompress_on_write){
        inflateEnd(&zs);
        decompress_on_write = false;
    }
}
    //static int scan_http_write_data_raw(const sbuf_t& buf) {
    //buf.raw_dump(data->fd, 0, buf.size());
    //return 0;
    //}

/**
 * on_message_begin:
 * Increment request nubmer. Note that the first request is request_no = 1
 */

int scan_http_cbo::on_message_begin()
{
    request_no ++;
    return 0;
}

int scan_http_cbo::on_url(const char *at, size_t length)
{
    return 0;
}


int scan_http_cbo::on_header_field(const char *at,size_t length)
{
    //const char * sbuf_head = reinterpret_cast<const char *>(data->sbuf->buf);
    //size_t offset = at - sbuf_head;
    //assert(offset < data->sbuf->size());
    //sbuf_t buf(*data->sbuf, offset, length);
        
    std::string field = sbuf.substr(sbuf.offset(reinterpret_cast<const uint8_t *>(at)),length);

    switch(header_state){
    case 1:
        /* we're a continuation of a partly-read header field */
        /* append it */
        header_field.append(field);
        break;
    case 2:
        /* we must have finished reading a value */
        /* add it to the map */
        headers[header_field] = header_value;
        break;
    default:
        /* store this field name */
        header_field = field;
        header_state = 1; /* indicate that we just read a header field */
    }
    return 0;
}

int scan_http_cbo::on_header_value(const char *at, size_t length)
{
    //const char * sbuf_head = reinterpret_cast<const char *>(data->sbuf->buf);
    //size_t offset = at - sbuf_head;
    //assert(offset < data->sbuf->size());
    //sbuf_t buf(*data->sbuf, offset, length);
        
    std::string value = sbuf.substr(sbuf.offset(reinterpret_cast<const uint8_t *>(at)),length);
    switch(header_state){
    case 2:
        /* we're a continuation of a partly-read header value */        
        header_value.append(value);
        break;
    default:
        /* we're a new header value */
        header_value = value;        /* store the value */
        header_state = 2;        /* indicate that we just read a header value */
        break;
    }
    return 0;
}

int scan_http_cbo::on_headers_complete()
{
    /* Add the most recently read header to the map, if any */
    if (header_state == 2) {
        headers[header_field] = header_value;
    }
        
    /* Set output path to <path>-HTTPBODY for the first body, -HTTPBODY-n for subsequent bodies
     * This is consistent with tcpflow <= 1.3.0, which supported only one HTTPBODY */
    std::stringstream os;
    os << path << "-HTTPBODY";
    if (request_no != 1) {
        os << "-" << request_no;
    }
        
    /* See if we can guess a file extension */
    std::string extension = get_extension_for_mime_type(headers["Content-Type"]);
    if (extension != "") {
        os << "." << extension;
    }
        
    output_path = os.str();
        
    /* Choose an output function based on the content encoding */
    std::string content_encoding(headers["Content-Encoding"]);
    if (content_encoding == "gzip" || content_encoding == "deflate") {
#ifdef HAVE_LIBZ
        DEBUG(10) ( "%s: detected zlib content, decompressing", output_path.c_str());
        decompress_on_write = true;
        //write_fn = scan_http_write_data_zlib;
#else
        /* We can't decompress, so just give it a .gz */
        output_path.append(".gz");
        //write_fn = scan_http_write_data_raw;
        DEBUG(5) ( "%s: refusing to decompress since zlib is unavailable", output_path.c_str() );
#endif
    } 
    //else {
    //        write_fn = scan_http_write_data_raw;
    //}
        
    /* Open the output path */
    fd = tcpdemux::getInstance()->retrying_open(output_path, O_WRONLY|O_CREAT|O_BINARY|O_APPEND, 0644);
    if (fd < 0) {
        DEBUG(1) ("unable to open HTTP body file %s", output_path.c_str());
    }
        
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
    /* Turn this back into an sbuf_t by mathing out the buffer offset */
    //const char * sbuf_head = reinterpret_cast<const char *>(data->sbuf->buf);
    //size_t offset = at - sbuf_head;
    //assert(offset < data->sbuf->size());
    //sbuf_t buf(*data->sbuf, offset, length);
    size_t offset = sbuf.offset(reinterpret_cast<const uint8_t *>(at));
    
    if(length==0) return 0;               // nothing to write
        
    if (fd < 0)  return -1;                // no open fd?

    /* Write this buffer to the output file via the appropriate method */
    if(decompress_on_write==false){
        int rv = sbuf.write(fd,offset,length);
        if(rv<0) return -1;
        bytes_written += rv;
    }
    else {
        /* allocate a z_stream if this is the first call */
        //bool needs_init = false;
        //if (data->write_fn_state == NULL) {
        //data->write_fn_state = calloc(1, sizeof(z_stream));
        //needs_init = true;
        //}
            
#ifdef HAVE_ZLIB
        /* set up this round of decompression, using a small local buffer */
        char decompressed[65536];
        zs.next_in = (Bytef*)buf.buf;
        zs.avail_in = buf.size();
        zs.next_out = (Bytef*)decompressed;
        zs.avail_out = sizeof(decompressed);
        
        /* is this our first call? */
        if (bytes_written==0) {
            int rv = inflateInit2(zs, 32 + MAX_WBITS);      /* 32 auto-detects gzip or deflate */
            if (rv != Z_OK) {
                /* fail! */
                DEBUG(3) ("decompression failed at stream initialization; bad Content-Encoding?");
                return -1;
            }
            zinit = true;
        }
        
        /* iteratively decompress, writing each time */
        while (zinit && (zs.avail_in > 0)) {
            /* decompress as much as possible */
            int rv = inflate(zs, Z_SYNC_FLUSH);
                
            if (rv == Z_STREAM_END) {
                /* are we done with the stream? */
                if (zs.avail_in > 0) {
                    /* ...no. */
                    DEBUG(3) ("decompression completed, but with trailing garbage");
                    return -2;
                }
            } else if (rv != Z_OK) {
                /* some other error */
                DEBUG(3) ("decompression failed (corrupted stream?)");
                return -3;
            }
                
            /* successful decompression, at least partly */
            /* write the result */
            int bytes_decompressed = sizeof(decompressed) - zs.avail_out;
            ssize_t written = write(fd, decompressed, bytes_decompressed);
            if (written < bytes_decompressed) {
                DEBUG(3) ("writing decompressed data failed");
                return -4;
            }
            bytes_written += written;
                
            /* reset the buffer for the next iteration */
            zs.next_out = (Bytef*)decompressed;
            zs.avail_out = sizeof(decompressed);
        }
#else
        assert(0);                      // shouldn't be able to get here
#endif        
    }
    return 0;
}


/* These are callbacks for the parser. Each one calls the appropriate method call */

int scan_http_cbo::on_message_complete()
{
    ///* Call the write function with an empty buffer to signal EOF */
    //sbuf_t empty_buffer(*data->sbuf, 0, 0);
    //data->write_fn(data, empty_buffer);
    //
    /* Close the file */
    close();
    return 0;
}


/***
 * data writing functions
 */

/* write data to a file with no decoding */



#if 0
/* write gzipped data to a file, decompressing it as we go */
int scan_http_write_data_zlib(scan_http_data_t * data, sbuf_t& buf) {
    z_stream *zs = reinterpret_cast<z_stream *>(data->write_fn_state);
    if (buf.size() == 0 && data->write_fn_state) {
        /* EOF */
        inflateEnd(zs);
        free(zs);
        return 0;
    }
        
    /* allocate a z_stream if this is the first call */
    bool needs_init = false;
    if (data->write_fn_state == NULL) {
        data->write_fn_state = calloc(1, sizeof(z_stream));
        needs_init = true;
    }
        
    /* set up this round of decompression, using a small local buffer */
    char decompressed[65536];
    zs->next_in = (Bytef*)buf.buf;
    zs->avail_in = buf.size();
    zs->next_out = (Bytef*)decompressed;
    zs->avail_out = sizeof(decompressed);
        
    /* is this our first call? */
    if (needs_init) {
        int rv = inflateInit2(zs, 32 + MAX_WBITS);      /* 32 auto-detects gzip or deflate */
        if (rv != Z_OK) {
            /* fail! */
            DEBUG(3) ("decompression failed at stream initialization; bad Content-Encoding?");
            return -1;
        }
    }
        
    /* iteratively decompress, writing each time */
    while (zs->avail_in > 0) {
        /* decompress as much as possible */
        int rv = inflate(zs, Z_SYNC_FLUSH);
                
        if (rv == Z_STREAM_END) {
            /* are we done with the stream? */
            if (zs->avail_in > 0) {
                /* ...no. */
                DEBUG(3) ("decompression completed, but with trailing garbage");
                return -2;
            }
        } else if (rv != Z_OK) {
            /* some other error */
            DEBUG(3) ("decompression failed (corrupted stream?)");
            return -3;
        }
                
        /* successful decompression, at least partly */
        /* write the result */
        int bytes_decompressed = sizeof(decompressed) - zs->avail_out;
        ssize_t written = write(data->fd, decompressed, bytes_decompressed);
        if (written < bytes_decompressed) {
            DEBUG(3) ("writing decompressed data failed");
            return -4;
        }
                
        /* reset the buffer for the next iteration */
        zs->next_out = (Bytef*)decompressed;
        zs->avail_out = sizeof(decompressed);
    }
        
    /* success! */
    return 0;
}
#endif



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
        return;         /* No feature files created */
    }

    if(sp.phase==scanner_params::scan){
        /* See if there is an HTTP response */
        if(sp.sbuf.memcmp(reinterpret_cast<const uint8_t *>("HTTP/1."),0,7)==0){
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
                        
            
            for(size_t offset=0;;){
                /* Set up a parser instance for the next chunk of HTTP responses and data.
                 * This might be repeated several times due to connection re-use and multiple requests.
                 * Note that the parser is not a C++ library but it can pass a "data" to the
                 * callback. We put the address for the scan_http_cbo object in the data and
                 * recover it with a cast in each of the callbacks.
                 */
                
                http_parser parser;
                http_parser_init(&parser, HTTP_RESPONSE);

                scan_http_cbo cbo(sp.sbuf.pos0.path, sp.sbuf);
                parser.data = &cbo;

                                
                /* Make an sbuf for the remaining data */
                sbuf_t sub_buf(sp.sbuf, offset);
                                
                /* Parse */
                size_t parsed = http_parser_execute(&parser, &scan_http_parser_settings,
                                                    reinterpret_cast<const char*>(sub_buf.buf), sub_buf.size());
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
        }
    }
}
