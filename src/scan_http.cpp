/**
 *
 * scan_http:
 * Decodes HTTP responses
 */

#include "config.h"
#include "tcpflow.h"
#include <iostream>
#include <sys/types.h>
#include "bulk_extractor_i.h"

extern "C"
void  scan_http(const class scanner_params &sp,const recursion_control_block &rcb)
{
    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_md5 requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::startup){
	sp.info->name  = "http";
	sp.info->flags = scanner_info::SCANNER_DISABLED; // default disabled
        return;     /* No feature files created */
    }

    if(sp.phase==scanner_params::scan){
	/* See if there is an HTTP response */
	if(sp.sbuf.memcmp(reinterpret_cast<const uint8_t *>("HTTP/1.1 "),0,9)==0){
	    /* Looks like a HTTP response. Split it at the \r\n\r\n into two sbufs and save each */
	    ssize_t body_start = sp.sbuf.find("\r\n\r\n",0);
	    if(body_start==-1) return;	// no body to be found

	    tcpdemux *d = tcpdemux::getInstance();

	    std::stringstream xml_head;
	    d->write_to_file(xml_head,sp.sbuf.pos0.path+"-HTTP",sbuf_t(sp.sbuf,0,body_start-2));

	    sbuf_t sbuf_body(sp.sbuf,body_start,sp.sbuf.bufsize - body_start);
	    std::stringstream xml_body;
	    d->write_to_file(xml_body,sp.sbuf.pos0.path+"-HTTPBODY",sbuf_body);

	    /* Need to do something with the XML */
	    /* Need to handle the gzip */
	}
    }
}
#if 0

	    struct stat st;
	    if(fstat(fd2,&st)==0){
		uint8_t *base = (uint8_t *)mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd2,0);
		const uint8_t *crlf = find_crlfcrlf(base,st.st_size);
		if(crlf){
		    ssize_t head_size = crlf - (const uint8_t *)base + 2;
		    write_to_file(xmladd,
				  flow_pathname+"-HTTP",
				  sbuf_t(pos0_t(),base,head_size,head_size,false));
		    if(st.st_size > head_size+4){
			size_t body_size = st.st_size - head_size - 4;
			write_to_file(xmladd,
				      flow_pathname+"-HTTPBODY",
				      sbuf_t(pos0_t()+head_size,crlf+4,body_size,body_size,false));
#ifdef HAVE_LIBZ
			if(opt.opt_gzip_decompress){
			    process_gzip(*this,xmladd,
					 flow_pathname+"-HTTPBODY-GZIP",(unsigned char *)crlf+4,body_size);
			}
#endif
		    }
		}
		munmap(base,st.st_size);
	    }
	}
    }
#endif
