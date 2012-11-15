/**
 *
 * scan_md5:
 * plug-in demonstration that shows how to write a simple plug-in scanner that calculates
 * the MD5 of each file..
 */

#include "config.h"
#include <iostream>
#include <sys/types.h>
#include "bulk_extractor_i.h"

extern "C"
void  scan_md5(const class scanner_params &sp,const recursion_control_block &rcb)
{
    std::cout << "scan_md5!!!!!!!!!! " << sp.phase << "\n";

    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_md5 requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    /* Check for phase 0 --- startup */
    if(sp.phase==scanner_params::startup){
	sp.info->name  = "md5";
	sp.info->flags = 0;
        return;     /* No feature files created */
    }

    /* Check for phase 2 --- shutdown */
    if(sp.phase==scanner_params::scan){
	std::string md5 = sp.sbuf.md5().hexdigest();
	std::cout << "md5=" << md5 << "\n";
    }
}
