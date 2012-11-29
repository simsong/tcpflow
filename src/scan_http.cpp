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


/***
 * data structures
 */

typedef struct scan_http_data_t;
typedef int(*write_data_fn_t)(scan_http_data_t * data, sbuf_t& buf);

/* define a data structure for sharing state between scan_http() and its callbacks */
typedef struct scan_http_data_t {
	std::string path;
	const sbuf_t * sbuf;
	tcpdemux *d;
	int request_no;
	
	/* parsed headers */
	std::map<std::string, std::string> headers;
	
	/* placeholders for possibly-incomplete header data */
	int header_state;
	std::string header_value, header_field;
	
	std::string output_path;
	
	int fd;
	write_data_fn_t write_fn;
	void * write_fn_state;
	
	scan_http_data_t(const std::string& path_, const sbuf_t * sbuf_, tcpdemux * d_) :
		path(path_), sbuf(sbuf_), d(d_), request_no(0),
		headers(), header_state(0), header_value(), header_field(),
		output_path(), fd(-1), write_fn(NULL), write_fn_state(NULL) {};
	
	scan_http_data_t(const scan_http_data_t& c) :
		path(c.path), sbuf(c.sbuf), d(c.d), request_no(c.request_no),
		headers(c.headers), header_state(c.header_state), header_value(c.header_value), header_field(c.header_field),
		output_path(c.output_path), fd(c.fd), write_fn(c.write_fn), write_fn_state(c.write_fn_state) {};
	
	void close_fd() {
		if ((fd >= 0) && (close(fd) != 0)) {
			perror("close() of http body");
		}
		fd = -1;
	};
};


/***
 * data writing functions
 */

/* write data to a file with no decoding */
int scan_http_write_data_raw(scan_http_data_t * data, sbuf_t& buf) {
	buf.raw_dump(data->fd, 0, buf.size());
	return 0;
}

#ifdef HAVE_LIBZ
#define ZLIB_CONST
#ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#  pragma GCC diagnostic ignored "-Wundef"
#  pragma GCC diagnostic ignored "-Wcast-qual"
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#define zs (reinterpret_cast<z_stream *>(data->write_fn_state))

/* write gzipped data to a file, decompressing it as we go */
int scan_http_write_data_zlib(scan_http_data_t * data, sbuf_t& buf) {
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
		int rv = inflateInit2(zs, 32 + MAX_WBITS);	/* 32 auto-detects gzip or deflate */
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

#undef zs

#endif


/***
 * http-parser callbacks
 */

/* make it easy to refer to the relevant scan_http_data within the callbacks */
#define data (reinterpret_cast<scan_http_data_t*>(parser->data))

int scan_http_cb_on_message_begin(http_parser * parser) {
	/* Bump the request number */
	/* Note that the first request is request_no = 1 */
	data->request_no ++;
	return 0;
}

int scan_http_cb_on_url(http_parser * parser, const char *at, size_t length) {
	return 0;
}

int scan_http_cb_on_header_field(http_parser * parser, const char *at, size_t length) {
	const char * sbuf_head = reinterpret_cast<const char *>(data->sbuf->buf);
	size_t offset = at - sbuf_head;
	assert(offset < data->sbuf->size());
	sbuf_t buf(*data->sbuf, offset, length);
	
	if (data->header_state == 1) {
		/* we're a continuation of a partly-read header field */
		/* append it */
		data->header_field.append(buf.asString());
	} else {
		/* we're a new header field */
		if (data->header_state == 2) {
			/* we must have finished reading a value */
			/* add it to the map */
			data->headers[data->header_field] = data->header_value;
		}
		
		/* store this field name */
		data->header_field = buf.asString();
		
		/* indicate that we just read a header field */
		data->header_state = 1;
	}
	
	return 0;
}

int scan_http_cb_on_header_value(http_parser * parser, const char *at, size_t length) {
	const char * sbuf_head = reinterpret_cast<const char *>(data->sbuf->buf);
	size_t offset = at - sbuf_head;
	assert(offset < data->sbuf->size());
	sbuf_t buf(*data->sbuf, offset, length);
	
	if (data->header_state == 2) {
		/* we're a continuation of a partly-read header value */
		data->header_value.append(buf.asString());
	} else {
		/* we're a new header value */
		/* store the value */
		data->header_value = buf.asString();
		
		/* indicate that we just read a header value */
		data->header_state = 2;
	}
	
	return 0;
}

int scan_http_cb_on_headers_complete(http_parser * parser) {
	/* Add the most recently read header to the map, if any */
	if (data->header_state == 2) {
		data->headers[data->header_field] = data->header_value;
	}
	
	/* Set output path to <path>-HTTPBODY for the first body, -HTTPBODY-n for subsequent bodies
	 * This is consistent with tcpflow <= 1.3.0, which supported only one HTTPBODY */
	std::stringstream output_path;
	output_path << data->path << "-HTTPBODY";
	if (data->request_no != 1) {
		output_path << "-" << data->request_no;
	}
	
	/* See if we can guess a file extension */
	std::string extension = get_extension_for_mime_type(data->headers["Content-Type"]);
	if (extension != "") {
		output_path << "." << extension;
	}
	
	data->output_path = output_path.str();
	
	/* Choose an output function based on the content encoding */
	std::string content_encoding(data->headers["Content-Encoding"]);
	if (content_encoding == "gzip" || content_encoding == "deflate") {
#ifdef HAVE_LIBZ
	DEBUG(10) ( "%s: detected zlib content, decompressing", data->output_path.c_str());
		data->write_fn = scan_http_write_data_zlib;
#else
		/* We can't decompress, but we can do something reasonable */
		data->output_path.append(".gz");
		data->write_fn = scan_http_write_data_raw;
		DEBUG(5) ( "%s: refusing to decompress since zlib is unavailable", data->output_path.c_str() );
#endif
	} else {
		data->write_fn = scan_http_write_data_raw;
	}
	
	/* Open the output path */
	data->fd = data->d->retrying_open(data->output_path, O_WRONLY|O_CREAT|O_BINARY|O_APPEND, 0644);
	if (data->fd < 0) {
		DEBUG(1) ("unable to open HTTP body file %s", data->output_path.c_str());
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

int scan_http_cb_on_body(http_parser * parser, const char *at, size_t length) {
	/* Turn this back into an sbuf_t by mathing out the buffer offset */
	const char * sbuf_head = reinterpret_cast<const char *>(data->sbuf->buf);
	size_t offset = at - sbuf_head;
	assert(offset < data->sbuf->size());
	sbuf_t buf(*data->sbuf, offset, length);
	
	if (data->fd >= 0) {
		/* Write this buffer to the output file via the appropriate function */
		int rv = data->write_fn(data, buf);
		if (rv) {
			/* failed! close early */
			data->close_fd();
		}
	}
	
	return 0;
}

int scan_http_cb_on_message_complete(http_parser * parser) {
	/* Call the write function with an empty buffer to signal EOF */
	sbuf_t empty_buffer(*data->sbuf, 0, 0);
	data->write_fn(data, empty_buffer);
	
	/* Close the file */
	data->close_fd();
	
	return 0;
}

#undef data



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
		return;		/* No feature files created */
	}

	if(sp.phase==scanner_params::scan){
		/* See if there is an HTTP response */
		if(sp.sbuf.memcmp(reinterpret_cast<const uint8_t *>("HTTP/1."),0,7)==0){
			/* Smells enough like HTTP to try parsing */
			/* Set up callbacks */
			http_parser_settings scan_http_parser_settings;
			scan_http_parser_settings.on_message_begin		= scan_http_cb_on_message_begin;
			scan_http_parser_settings.on_url				= scan_http_cb_on_url;
			scan_http_parser_settings.on_header_field		= scan_http_cb_on_header_field;
			scan_http_parser_settings.on_header_value		= scan_http_cb_on_header_value;
			scan_http_parser_settings.on_headers_complete	= scan_http_cb_on_headers_complete;
			scan_http_parser_settings.on_body				= scan_http_cb_on_body;
			scan_http_parser_settings.on_message_complete	= scan_http_cb_on_message_complete;
			
			/* Set up a struct for our callbacks */
			scan_http_data_t data(sp.sbuf.pos0.path, &sp.sbuf, tcpdemux::getInstance());
			
			/* Process the whole stream in a loop, since there could be multiple requests */
			size_t offset = 0;
			while (1) {
				/* Set up the parser itself */
				http_parser parser;
				http_parser_init(&parser, HTTP_RESPONSE);
				parser.data = &data;
				
				/* Make an sbuf for the remaining data */
				sbuf_t sub_buf(sp.sbuf, offset);
				
				/* Parse */
				size_t parsed = http_parser_execute(&parser, &scan_http_parser_settings, reinterpret_cast<const char*>(sub_buf.buf), sub_buf.size());
				assert(parsed <= sub_buf.size());
				
				/* Indicate EOF (flushing callbacks) and terminate if we parsed the entire buffer */
				if (parsed == sub_buf.size()) {
					http_parser_execute(&parser, &scan_http_parser_settings, NULL, 0);
					break;
				}
				
				/* Stop parsing if we parsed nothing */
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
