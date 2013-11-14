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


/** callback called by process_packet()
 */ 
static void packet_handler(void *user,const be13::packet_info &pi)
{
    reinterpret_cast<tcpdemux *>(user)->process_pkt(pi);
}

extern "C"
void  scan_tcpdemux(const class scanner_params &sp,const recursion_control_block &rcb)
{

    if(sp.sp_version!=scanner_params::CURRENT_SP_VERSION){
	std::cerr << "scan_tcpdemux requires sp version " << scanner_params::CURRENT_SP_VERSION << "; "
		  << "got version " << sp.sp_version << "\n";
	exit(1);
    }

    if(sp.phase==scanner_params::PHASE_STARTUP){
	sp.info->name  = "tcpdemux";
	sp.info->author= "Simson Garfinkel";
	sp.info->packet_user = tcpdemux::getInstance();
	sp.info->packet_cb = packet_handler;
        
        sp.info->get_config("tcp_timeout",&tcpdemux::getInstance()->tcp_timeout,"Timeout for TCP connections");

        return;     /* No feature files created */
    }

    if(sp.phase==scanner_params::PHASE_SCAN){
	static const std::string hash0("<hashdigest type='TCPDEMUX'>");
	static const std::string hash1("</hashdigest>");
	return;
    }
}
