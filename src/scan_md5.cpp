/**
 *
 * scan_md5:
 * plug-in demonstration that shows how to write a simple plug-in scanner that calculates
 * the MD5 of each file..
 */

#include "config.h"
#include "bulk_extractor_i.h"
#include "dfxml/src/hash_t.h"

#include <iostream>
#include <sys/types.h>


extern "C"
void  scan_md5(const class scanner_params &sp,const recursion_control_block &rcb)
{

    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_md5 requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
	sp.info->name  = "md5";
	sp.info->flags = scanner_info::SCANNER_DISABLED;
        return;     /* No feature files created */
    }

#ifdef HAVE_EVP_GET_DIGESTBYNAME
    if(sp.phase==scanner_params::PHASE_SCAN){
	static const std::string hash0("<hashdigest type='MD5'>");
	static const std::string hash1("</hashdigest>");
	if(sp.sxml){
            (*sp.sxml) << hash0 << dfxml::md5_generator::hash_buf(sp.sbuf.buf,sp.sbuf.bufsize).hexdigest() << hash1;
        }
	return;
    }
#endif
}
