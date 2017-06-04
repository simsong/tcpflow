/** vi:ft=cpp ts=8 et sw=4 sts=4 tw=80
 *  emacs: -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 8; c-file-style: "linux" -*-
 *
 * scan_python:
 * Use external python script
 */

#include "config.h"
#include "dfxml/src/hash_t.h"
#include "tcpflow.h"

#include <iostream>
#include <sys/types.h>

#if HAVE_PYTHON2_7_PYTHON_H
#  include <python2.7/Python.h> // Get header: install package "python-devel"
#endif


struct ScanPython
{
    ScanPython() : path(), module(), function(), initializationScript(),
#if HAVE_PYTHON2_7_PYTHON_H
        pythonFunction (NULL)
#endif
    { }

    ScanPython(const ScanPython& o) : path(o.path), module(o.module), function(o.function), initializationScript(o.initializationScript),
#if HAVE_PYTHON2_7_PYTHON_H
        pythonFunction (NULL)
#endif
    { }

    ScanPython& operator=(const ScanPython& o) {
        path                 = o.path;
        module               = o.module;
        function             = o.function;
        initializationScript = o.initializationScript;
#if HAVE_PYTHON2_7_PYTHON_H
        pythonFunction = NULL;
#endif
        return *this;
    }

    void startup(const scanner_params& sp);
    void init();
    void before();
    void scan(const scanner_params& sp);
    void shutdown();

    std::string path;
    std::string module;
    std::string function;
    std::string initializationScript;

#if HAVE_PYTHON2_7_PYTHON_H
    PyObject* pythonFunction;
#endif
};


void ScanPython::startup(const scanner_params& sp)
{
    if (sp.sp_version != scanner_params::CURRENT_SP_VERSION) {
        std::cerr << "scan_python requires sp version "
                  << scanner_params::CURRENT_SP_VERSION << "; "
                  << "got version " << sp.sp_version << "\n";
        exit(1);
    }

    sp.info->name = "python";
    sp.info->flags = scanner_info::SCANNER_DISABLED;

    sp.info->get_config("pyPath", &path, "    Directory to find python module (optional)");
    sp.info->get_config("pyModule", &module, "  Name of python module (script name without extension)");
    sp.info->get_config("pyFunction", &function, "Function name within the python module");
}


static std::string get_working_dir(const std::string& path)
{
    if (path.empty()) {
        return "os.getcwd()";
    }
    if (path[0] == '/'){
        return "'" + path + "'";
    } else {
        return "os.getcwd() + '/" + path + "'";
    }
}

void ScanPython::init()
{
    if (module.empty() || function.empty()) {
        DEBUG(2)("[scan_python] Cannot call python becase no provided module/function.\n"
                 "              Please use arguments -S pyModule=module -S pyFunction=foo");
        return;
    }

    // Write the initialization script to set directory to the local system path
    initializationScript = "import sys, os"                          "\n"
                           "workingDir = " + get_working_dir(path) + "\n"
                           "sys.path.append(workingDir)"             "\n";

#if HAVE_PYTHON2_7_PYTHON_H
    // Spawn python interpreter
    Py_Initialize();

    DEBUG(10) ("[scan_python]  Initialize Python using script:" "\n" "%s", initializationScript.c_str());
    PyRun_SimpleString(initializationScript.c_str());

    // Create PyObject from script filename
    PyObject* pName = PyString_FromString(module.c_str());
    if (pName == NULL) {
        DEBUG(2) ("[scan_python] Cannot create PyObject from path='%s' and module='%s'"
                  "Try using three arguments: -S pyPath=path -S pyModule=module -S pyFunction=foo",
                  path.c_str(), module.c_str());
        return;
    }

    // Import script file in python interpreter
    PyObject* pModule = PyImport_Import(pName);
    if (pModule == NULL) {
        DEBUG(2) ("[scan_python] Cannot import module='%s' from path='%s' in Python interpreter"
                  "Try using three arguments: -S pyPath=path -S pyModule=module -S pyFunction=foo",
                  module.c_str(), path.c_str());
        return;
    }

    // Identify function to be used
    pythonFunction = PyObject_GetAttrString(pModule, function.c_str());
    if (pythonFunction == NULL) {
        DEBUG(2) ("[scan_python] Cannot identify function='%s' in module='%s' from path='%s'"
                  "Try using three arguments: -S pyPath=path -S pyModule=module -S pyFunction=foo",
                  function.c_str(), module.c_str(), path.c_str());
        return;
    }
#endif
}


void ScanPython::before()
{
}


void ScanPython::scan(const scanner_params& sp)
{
#if HAVE_PYTHON2_7_PYTHON_H
    if (pythonFunction == NULL) {
        init();
        if (pythonFunction == NULL)
            return;
    }

    // Cast packet buffer contents into a string and create pyObject
    std::string data(reinterpret_cast<char const*>(sp.sbuf.buf));
    PyObject* pData = PyString_FromString(data.c_str());

    // Compose python argument in the form of a tuple and pass the argument to
    // the chosen function; if the function does not return anything or
    // encounters an error, return to exit and/or display the error
    PyObject* pArgs = PyTuple_New(1);
    PyTuple_SetItem(pArgs, 0, pData);
    PyObject* pResult = PyObject_CallObject(pythonFunction, pArgs);
    if (pResult) {
        // If XML-reporting enabled => Insert the returned string from the function
        if (sp.sxml) {
            const char* ptr = PyString_AsString(pResult);
            if (ptr)
                (*sp.sxml) << "<scan_python_result>"<< ptr <<"</scan_python_result>";
            else
                (*sp.sxml) << "<scan_python_result/>";
        }
    }
#else
    DEBUG(2)
    ("[scan_python] tcpflow cannot call python scripts required by the scanner 'python' "
     "because the header <python2.7/Python.h> was not present during the tcpflow build. "
     "Try to install package 'python-devel' and build again tcpflow (./configure)");
#endif
}


void ScanPython::shutdown()
{
#if HAVE_PYTHON2_7_PYTHON_H
    // Terminate the python interpreter and exit
    Py_Finalize();
    pythonFunction = NULL;
#endif
}


extern "C" void scan_python(const scanner_params& sp,
                            const recursion_control_block& /*rcb*/)
{
    static ScanPython singleton;

    switch (sp.phase) {

    case scanner_params::PHASE_NONE:
        break;

    // Called in main thread to parse configuration
    // (also used to build the --help text)
    case scanner_params::PHASE_STARTUP:
        singleton.startup(sp);
        break;

    // Should be called in main thread after all scanners loaded (but never called)
    case scanner_params::PHASE_INIT:
        singleton.init();
        break;

    // Called in worker thread before first scan
    case scanner_params::PHASE_THREAD_BEFORE_SCAN:
        singleton.before();
        break;

    // Called in worker thread for each sbuf
    case scanner_params::PHASE_SCAN:
        singleton.scan(sp);
        break;

    // Called in main thread when scanner is shutdown
    case scanner_params::PHASE_SHUTDOWN:
        singleton.shutdown();
        break;
    }
}
