/**
 *
 * scan_custom;
 */

#include "config.h"
#include "bulk_extractor_i.h"
#include "dfxml/src/hash_t.h"

#include <iostream>
#include <sys/types.h>


extern "C"
void  scan_custom(const class scanner_params &sp,const recursion_control_block &rcb)
{

    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_custom requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
	sp.info->name  = "custom";
	sp.info->flags = scanner_info::SCANNER_DISABLED;
        return;     /* No feature files created */
    }

#ifdef HAVE_EVP_GET_DIGESTBYNAME
    if(sp.phase==scanner_params::PHASE_SCAN){
	printf("Hello world!\n");
	//fwrite(sp.sbuf.buf,sp.sbuf.bufsize,1,stdout);
	return;
    }
#endif
}
