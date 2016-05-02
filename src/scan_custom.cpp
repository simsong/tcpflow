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
	
	// TODO:
	// ADD COMMAND LINE ARCHITECTURE (Partially complete: requires passage of optarg to this file)
	
	Py_Initialize();
	PyObject *pName, *pModule, *pFunc, *pArgs, *pData, *pResult;
	
	std::string data( reinterpret_cast< char const* >(sp.sbuf.buf) );
	pData = PyString_FromString(data.c_str());

	//os.getcwd() should return "/home/smolesss/git/tcpflow"
	PyRun_SimpleString("import sys, os\n" "workingDir = os.getcwd() + '/build'\n" "sys.path.append(workingDir)\n");
	
	pName = PyString_FromString("myPlugin"); // commandline arg will determine
	pModule=PyImport_Import(pName);
	pFunc=PyObject_GetAttrString(pModule,"myFunction"); // commandline arg will determine
	pArgs = PyTuple_New(1);
	PyTuple_SetItem(pArgs,0,pData);
	pResult = PyObject_CallObject(pFunc,pArgs);

	//printf("Plugin returned:\n %s\n", PyString_AsString(pResult));	
	
	if(sp.sxml) {
		(*sp.sxml) << "<plugindata>" << PyString_AsString(pResult) << "</plugindata>";
	}

	Py_Finalize();
	return;
    }
#endif
}
