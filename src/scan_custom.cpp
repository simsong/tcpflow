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

// Iimport the global variable that holds our commandline argument for -P
extern std::string pyPluginArg;

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
	
	// Debug print statement which prints the application data buffer contents
	// printf("%.*s\n##########################\n",sp.sbuf.bufsize,sp.sbuf.buf);
		
	std::string pluginName;
	std::string functionName;
	
	// Find delimeter in commandline argument to identify where to split the argument
	int delimIndex = pyPluginArg.find("::");
	if (delimIndex < 0) {
		printf("Invalid argument to option 'P'. Must follow: <filename>::<function>.\n");
		return;
	}
	
	// Split the argument
	pluginName = pyPluginArg.substr(0,delimIndex);
	functionName = pyPluginArg.substr(delimIndex+2);

	// Spawn python interpreter and define python objects
	Py_Initialize();
	PyObject *pName, *pModule, *pFunc, *pArgs, *pData, *pResult;
	
	// Cast packet buffer contents into a string and then create pyObject from string
	std::string data(reinterpret_cast<char const*>(sp.sbuf.buf));
	pData = PyString_FromString(data.c_str());
	
	// Add the plugin directory to the local system path
	PyRun_SimpleString("import sys, os\n" "workingDir = os.getcwd() + '/python/plugins'\n" "sys.path.append(workingDir)\n");

	// Create pyObject from plugin file name (string)
	pName = PyString_FromString(pluginName.c_str());
	
	// Import plugin file in python interpreter; if an import error occurs, return to display the error
	pModule=PyImport_Import(pName);
	if (pModule==NULL) return;

	// Identify plugin function to be used; if an assignment error occurs, return to display the error
	pFunc=PyObject_GetAttrString(pModule,functionName.c_str());
	if (pFunc==NULL) return;
	
	// Compose python argument in the form of a tuple and pass the argument to the chosen function; if the function does not return anything or encounters an error, return to display the error
	pArgs = PyTuple_New(1);
	PyTuple_SetItem(pArgs,0,pData);
	pResult = PyObject_CallObject(pFunc,pArgs);
	if (pResult==NULL) return;
	
	// If xml-reporting is enabled, insert the string the function returned into the report
	if(sp.sxml) {
		(*sp.sxml) << "<plugindata>\n" << PyString_AsString(pResult) << "\n</plugindata>";
	}
	
	// Terminate the python interpreter and exit
	Py_Finalize();
	return;
    }
#endif
}
