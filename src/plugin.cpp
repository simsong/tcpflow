/*
 * common.cpp:
 * bulk_extractor backend stuff, used for both standalone executable and bulk_extractor.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif

#include "bulk_extractor_i.h"
#include "xml.h"

uint32_t scanner_def::max_depth = 5;		// max recursion depth

/****************************************************************
 *** misc support
 ****************************************************************/

void be_mkdir(string dir)
{
#ifdef WIN32
    if(mkdir(dir.c_str())){
	cerr << "Could not make directory " << dir << "\n";
	exit(1);
    }
#else
    if(mkdir(dir.c_str(),0777)){
	cerr << "Could not make directory " << dir << "\n";
	exit(1);
    }
#endif
}

#ifndef HAVE_ERR
#include <stdarg.h>
static void err(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  va_end(ap);
  fprintf(stderr,": %s\n",strerror(errno));
  exit(eval);
}
#endif

#ifndef HAVE_ERRX
#include <stdarg.h>
static void errx(int eval,const char *fmt,...)
{
  va_list ap;
  va_start(ap,fmt);
  vfprintf(stderr,fmt,ap);
  fprintf(stderr,"%s\n",strerror(errno));
  va_end(ap);
  exit(eval);
}
#endif

/****************************************************************
 *** SCANNER PLUG-IN SYSTEM
 ****************************************************************/

scanner_params::PrintOptions scanner_params::no_options; 
scanner_vector current_scanners;				// current scanners
/**
 * return true a scanner is enabled
 */

/* enable or disable a specific scanner.
 * enable = 0  - disable that scanner.
 * enable = 1  - enable that scanner
 * 'all' is a special scanner that enables all scanners.
 */

void set_scanner_enabled(const string name,bool enable)
{
    for(scanner_vector::iterator it = current_scanners.begin();it!=current_scanners.end();it++){
	if(name=="all" && (((*it)->info.flags & scanner_info::SCANNER_NO_ALL)==0)){
	    (*it)->enabled = enable;
	}
	if((*it)->info.name==name){
	    (*it)->enabled = enable;
	    return;
	}
    }
    if(name=="all") return;
    cerr << "Invalid scanner name '" << name << "'\n";
    exit(1);
}

void disable_all_scanners()
{
    for(scanner_vector::const_iterator it = current_scanners.begin();it!=current_scanners.end();it++){
	(*it)->enabled = false;
    }
}

/** Name of feature files that should be histogramed.
 * The histogram should be done in the plug-in
 */

histograms_t histograms;

/**
 * plugin system phase 0: Load a scanner.
 */
void load_scanner(const scanner_t &scanner,histograms_t &hg)
{
    /* If scanner is already loaded, return */
    for(scanner_vector::const_iterator it = current_scanners.begin();it!=current_scanners.end();it++){
	if((*it)->scanner==&scanner) return;
    }

    pos0_t	pos0;
    sbuf_t	sbuf(pos0);
    feature_recorder_set fs(feature_recorder_set::DISABLED); // dummy
    scanner_params sp(scanner_params::startup,sbuf,fs);	// 
    
    scanner_def *sd = new scanner_def(); // will keep
    sd->scanner = scanner;

    sp.phase = scanner_params::startup;				// startup
    sp.info  = &sd->info;

    recursion_control_block rcb(0,"",0); // empty rcb
    (*scanner)(sp,rcb);			 // phase 0
    
    sd->enabled      = !(sd->info.flags & scanner_info::SCANNER_DISABLED);

    for(histograms_t::const_iterator it = sd->info.histogram_defs.begin();
	it != sd->info.histogram_defs.end(); it++){
	hg.insert((*it));
    }
    current_scanners.push_back(sd);
}



#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

static void load_scanner_file(string fn,histograms_t &hg)
{
    /* Figure out the function name */
    size_t extloc = fn.rfind('.');
    if(extloc==string::npos){
	errx(1,"Cannot find '.' in %s",fn.c_str());
    }
    string func_name = fn.substr(0,extloc);
    size_t slashloc = func_name.rfind('/');
    if(slashloc!=string::npos) func_name = func_name.substr(slashloc+1);
    slashloc = func_name.rfind('\\');
    if(slashloc!=string::npos) func_name = func_name.substr(slashloc+1);

    std::cout << "Loading: " << fn << " (" << func_name << ")\n";
    scanner_t *scanner = 0;
#if defined(HAVE_DLOPEN)
    void *lib=dlopen(fn.c_str(), RTLD_LAZY);

    if(lib==0){
	errx(1,"dlopen: %s\n",dlerror());
    }

    /* Resolve the symbol */
    scanner = (scanner_t *)dlsym(lib, func_name.c_str());

    if(scanner==0) errx(1,"dlsym: %s\n",dlerror());
#elif defined(HAVE_LOADLIBRARY)
    /* Use Win32 LoadLibrary function */
    /* See http://msdn.microsoft.com/en-us/library/ms686944(v=vs.85).aspx */
    HINSTANCE hinstLib = LoadLibrary(TEXT(fn.c_str()));
    if(hinstLib==0) errx(1,"LoadLibrary(%s) failed",fn.c_str());
    scanner = (scanner_t *)GetProcAddress(hinstLib,func_name.c_str());
    if(scanner==0) errx(1,"GetProcAddress(%s) failed",func_name.c_str());
#else
    std::cout << "  ERROR: Support for loadable libraries not enabled\n";
    return;
#endif
    load_scanner(*scanner,hg);
}

void load_scanners(const scanner_t *scanners[],histograms_t &hg)
{
    for(int i=0;scanners[i];i++){
	load_scanner(*scanners[i],hg);
    }
}


void load_scanner_directory(const string &dirname,histograms_t &hg)
{
    DIR *dirp = opendir(dirname.c_str());
    if(dirp==0){
	err(1,"Cannot open directory %s:",dirname.c_str());
    }
    struct dirent *dp;
    while ((dp = readdir(dirp)) != NULL){
	string fname = dp->d_name;
	if(fname.substr(0,5)=="scan_" || fname.substr(0,5)=="SCAN_"){
	    size_t extloc = fname.rfind('.');
	    if(extloc==string::npos) continue; // no '.'
	    string ext = fname.substr(extloc+1);
#ifdef WIN32
	    if(ext!="DLL") continue;	// not a DLL
#else
	    if(ext!="so") continue;	// not a shared library
#endif
	    load_scanner_file(dirname+"/"+fname,hg);
	}
    }
}


/* Finish scanners */
/****************************************************************
 *** PHASE_SHUTDOWN (formerly phase 2): shut down the scanners
 ****************************************************************/

void phase_shutdown(feature_recorder_set &fs, xml &xreport)
{
    for(scanner_vector::iterator it = current_scanners.begin();it!=current_scanners.end();it++){
	if((*it)->enabled){
	    pos0_t pos0;
	    sbuf_t sbuf(pos0);
	    scanner_params sp(scanner_params::shutdown,sbuf,fs);
	    recursion_control_block rcb(0,"",0);	// empty rcb 
	    sp.phase=scanner_params::shutdown;				// shutdown
	    (*(*it)->scanner)(sp,rcb);
	}
    }
}

/****************************************************************
 *** PHASE HISTOGRAM (formerly phase 3): Create the histograms
 ****************************************************************/
#ifdef USE_HISTOGRAMS
void phase_histogram(feature_recorder_set &fs, xml &xreport)
{
    int ctr = 0;
    for(histograms_t::const_iterator it = histograms.begin();it!=histograms.end();it++){
	std::cout << "   " << (*it).feature << " " << (*it).suffix << "...";
	if(fs.has_name((*it).feature)){
	    feature_recorder *fr = fs.get_name((*it).feature);
	    try {
		fr->make_histogram((*it));
	    }
	    catch (const std::exception &e) {
		std::cerr << "ERROR: " ;
		std::cerr.flush();
		std::cerr << e.what() << " computing histogram " << (*it).feature << "\n";
		xreport.xmlout("error",(*it).feature, "function='phase3'",true);
	    }
	}
	if(++ctr % 3 == 0) std::cout << "\n";
	std::cout.flush();
    }
    if(ctr % 4 !=0) std::cout << "\n";
    xreport.comment("phase 3 finish");
    xreport.flush();
}
#endif

void enable_feature_recorders(feature_file_names_t &feature_file_names)
{
    feature_file_names.insert(feature_recorder_set::ALERT_RECORDER_NAME); // we always have alerts
    for(scanner_vector::const_iterator it=current_scanners.begin();it!=current_scanners.end();it++){
	if((*it)->enabled){
	    for(set<string>::const_iterator fi=(*it)->info.feature_names.begin();
		fi!=(*it)->info.feature_names.end();
		fi++){
		feature_file_names.insert(*fi);
	    }
	}
    }
}
