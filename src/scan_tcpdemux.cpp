/**
 * tcp demultiplixier scanner.
 *
 * We have a single global tcpdemultiplixer because it needs to manage
 * a global resource --- the maximum number of open files.  We get the
 * singleton instance and put it in the user argument of the global
 * callback array. We could have designed the callback system to take
 * an instance which is subclassed from an abstract superclass, but
 * that would require a virtual function resolution on every function
 * call, whereas here we simply have a function call with two
 * arguments (which is faster, but less safe.)
 */

#include "config.h"
#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"
#include <iostream>
#include <sys/types.h>
#include "bulk_extractor_i.h"


static void packet_handler(void *user,const packet_info &pi)
{
    reinterpret_cast<tcpdemux *>(user)->process_ip(pi.ts,pi.data,pi.caplen,pi.vlan);
}

extern "C"
void  scan_tcpdemux(const class scanner_params &sp,const recursion_control_block &rcb)
{

    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_tcpdemux requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::startup){
	sp.info->name  = "tcpdemux";
	sp.info->author= "Simson Garfinkel";
	sp.info->packet_user = tcpdemux::getInstance();
	sp.info->packet_cb = packet_handler;
        return;     /* No feature files created */
    }

    if(sp.phase==scanner_params::scan){
	static const std::string hash0("<hashdigest type='TCPDEMUX'>");
	static const std::string hash1("</hashdigest>");
	return;
    }
}
