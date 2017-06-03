/** emacs: -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 8; c-file-style: "linux" -*-
 *  vi:ft=cpp ts=8 et sw=4 sts=4 tw=80
 *
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
    void startup(const scanner_params& sp);
    void init(const scanner_params& sp);
    void before(const scanner_params& sp);
    void scan(const scanner_params& sp);
    void shutdown(const scanner_params& sp);

    std::string scriptFullPath;
    std::string scriptDirectory;
    std::string scriptFilename;
    std::string functionName;
    std::string initializationScript;

#if HAVE_PYTHON2_7_PYTHON_H
    PyObject* pythonFunction = NULL; // requires C++11
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

    sp.info->get_config("pyScript", &scriptFullPath, "pathname of a tcpdump-compatible python script");
    sp.info->get_config("pyFunction", &functionName, "function name within the python script");
}


void ScanPython::init(const scanner_params& /*sp*/)
{
#ifndef HAVE_PYTHON2_7_PYTHON_H
    DEBUG(2)
    ("tcpflow cannot call python scripts required by the scanner_python "
     "because the header <python2.7/Python.h> was not present during the tcpflow build. "
     "Try to install package 'python-devel' and build again tcpflow (./configure)");
#endif

    if (scriptFullPath.empty() || functionName.empty()) {
        DEBUG(2)("[scan_python] Cannot call python becase no script/function is provided."
                 " Please use arguments -S pyScript=dir/script.py -S pyFunction=foo.");
    }

    // Write the initialization script to set directory to the local system path
    initializationScript = "import sys, os"  "\n"
                           "workingDir = ";
    // Split directory/filename
    size_t delimeter_index = scriptFullPath.rfind("/");
    if (delimeter_index == std::string::npos) {
        scriptDirectory = ".";
        scriptFilename = scriptFullPath;
        initializationScript += "os.getcwd()";
    } else {
        scriptDirectory = scriptFullPath.substr(0, delimeter_index);
        scriptFilename = scriptFullPath.substr(delimeter_index + 1);
        initializationScript += (scriptDirectory[0] == '/') ? "'" : "os.getcwd() + '/";
        initializationScript += scriptDirectory + "'";
    }
    initializationScript += "\n" "sys.path.append(workingDir)" "\n";

#if HAVE_PYTHON2_7_PYTHON_H
    // Spawn python interpreter
    Py_Initialize();

    DEBUG(10)
    ("Initialize Python using script:" "\n" "%s",
        initializationScript.c_str());
    PyRun_SimpleString(initializationScript.c_str());

    // Create PyObject from script filename
    PyObject* pName = PyString_FromString(scriptFilename.c_str());
    if (pName == NULL) {
        DEBUG(2)
        ("Cannot create PyObject from script filename '%s'", scriptFilename.c_str());
        return;
    }

    // Import script file in python interpreter
    PyObject* pModule = PyImport_Import(pName);
    if (pModule == NULL) {
        DEBUG(2)
        ("Cannot import script '%s' in Python interpreter", scriptFilename.c_str());
        return;
    }

    // Identify function to be used
    pythonFunction = PyObject_GetAttrString(pModule, functionName.c_str());
    if (pythonFunction == NULL) {
        DEBUG(2)
        ("Cannot identify function '%s' in python script '%s'", functionName.c_str(), scriptFilename.c_str());
        return;
    }
#endif
}


void ScanPython::before(const scanner_params& /*sp*/)
{
}


void ScanPython::scan(const scanner_params& sp)
{
#if HAVE_PYTHON2_7_PYTHON_H
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
            (*sp.sxml) << "<plugindata>"
                       << PyString_AsString(pResult)
                       << "</plugindata>";
        }
    }
#endif
}


void ScanPython::shutdown(const scanner_params& /*sp*/)
{
#if HAVE_PYTHON2_7_PYTHON_H
    // Terminate the python interpreter and exit
    Py_Finalize();
#endif
}


extern "C" void scan_python(const scanner_params& sp,
                            const recursion_control_block& /*rcb*/)
{
    static ScanPython singleton;

    switch (sp.phase) {

    case scanner_params::PHASE_NONE:
        break;

    // called in main thread to parse configuration
    // (also used to build the --help text)
    case scanner_params::PHASE_STARTUP:
        singleton.startup(sp);
        break;

    // called in main thread after all scanners loaded
    case scanner_params::PHASE_INIT:
        singleton.init(sp);
        break;

    // called in worker thread before first scan
    case scanner_params::PHASE_THREAD_BEFORE_SCAN:
        singleton.before(sp);
        break;

    // called in worker thread for each sbuf
    case scanner_params::PHASE_SCAN:
        singleton.scan(sp);
        break;

    // called in main thread when scanner is shutdown
    case scanner_params::PHASE_SHUTDOWN:
        singleton.shutdown(sp);
        break;
    }
}
