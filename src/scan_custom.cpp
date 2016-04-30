/**
 *
 * scan_custom;
 */

#include "config.h"
#include "bulk_extractor_i.h"
#include "dfxml/src/hash_t.h"

#include <iostream>
#include <sys/types.h>
#include <python2.7/Python.h>

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
	//printf("%.*s\n##########################\n",sp.sbuf.bufsize,sp.sbuf.buf);
	// MUST PASS DATA BACK FOR WRITING	
	Py_Initialize();
	std::string data( reinterpret_cast< char const* >(sp.sbuf.buf) );
	char functionString[128];
	char moduleString[128];
	strcpy(functionString,"myFunction"); // will be a commandline arg
	strcat(functionString,"()");
	strcpy(moduleString,"from ");
	strcat(moduleString,"myPlugin"); // will be commandline arg
	strcat(moduleString," import ");
	strcat(moduleString,"myFunction"); // will be commandline arg
	PyRun_SimpleString(

		"import sys\n"
		"sys.path.append('/home/smolesss/git/tcpflow/build')\n"

		); // TODO: Append relative path to build!
	PyRun_SimpleString(moduleString);
	PyRun_SimpleString(functionString);

	
	//Alternative printing:
	//std::cout << data;
	
	
	Py_Finalize();
	return;
    }
#endif
}
