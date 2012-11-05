#ifndef BULK_EXTRACTOR_I_H
#define BULK_EXTRACTOR_I_H

/**
 * \addtogroup plugin_module
 * @{
 */

/**
 * \file
 * bulk_extractor scanner plug_in architecture.
 *
 * Scanners are called with two parameters:
 * A reference to a scanner_params (SP) object.
 * A reference to a recursion_control_block (RCB) object.
 * 
 * On startup, each scanner is called with a special SP and RCB.
 * The scanners respond by setting fields in the SP and returning.
 * 
 * When executing, once again each scanner is called with the SP and RCB.
 * By design, this file can be read without reading config.h
 * This is the only file that needs to be included for a scanner.
 *
 * \li \c phase_startup - scanners are loaded and register the names of the feature files they want.
 * \li \c phase_scan - each scanner is called to analyze 1 or more sbufs.
 * \li \c phase_shutdown - scanners are given a chance to shutdown
 */

#ifndef	__cplusplus
#error bulk_extractor_i.h requires C++
#endif

#include "sbuf.h"
#include "cppmutex.h"
#include "feature_recorder.h"
#include "feature_recorder_set.h"
#include "utf8.h"

#include <vector>
#include <set>

/**
 * \class scanner_params
 * The scanner params class is the primary way that the bulk_extractor framework
 * communicates with the scanners. 
 * @param sbuf - the buffer to be scanned
 * @param feature_names - if fs==0, add to feature_names the feature file types that this
 *                        scanner records.. The names can have a /c appended to indicate
 *                        that the feature files should have context enabled. Do not scan.
 * @param fs   - where the features should be saved. Must be provided if feature_names==0.
 **/

class histogram_def {
 public:
    /**
     * @param feature- the feature file to histogram (no .txt)
     * @param re     - the regular expression to extract
     * @param require- require this string on the line (usually in context)
     * @param suffix - the suffix to add to the histogram file after feature name before .txt
     * @param flags  - any flags (see above)
     */

    histogram_def(string feature_,string re_,string suffix_,uint32_t flags_=0):
	feature(feature_),pattern(re_),require(),suffix(suffix_),flags(flags_){}
    histogram_def(string feature_,string re_,string require_,string suffix_,uint32_t flags_=0):
	feature(feature_),pattern(re_),require(require_),suffix(suffix_),flags(flags_){}
    string feature;			/* feature file */
    string pattern;			/* extract pattern; "" means use entire feature */
    string require;
    string suffix;			/* suffix to append; "" means "histogram" */
    uint32_t flags;			// defined in histogram.h
};

typedef  set<histogram_def> histograms_t;

inline bool operator <(class histogram_def h1,class histogram_def h2)  {
    if (h1.feature<h2.feature) return true;
    if (h1.feature>h2.feature) return false;
    if (h1.pattern<h2.pattern) return true;
    if (h1.pattern>h2.pattern) return false;
    if (h1.suffix<h2.suffix) return true;
    if (h1.suffix>h2.suffix) return false;
    return false;			/* equal */
};


inline bool operator !=(class histogram_def h1,class histogram_def h2)  {
    return h1.feature!=h2.feature || h1.pattern!=h2.pattern || h1.suffix!=h2.suffix;
};

typedef void scanner_t(const class scanner_params &sp,const class recursion_control_block &rcb);
typedef void process_t(const class scanner_params &sp); 

/** scanner_info gets filled in by the scanner to tell the caller about the scanner.
 */
class scanner_info {
 public:
    static const int SCANNER_DISABLED=0x01;		/* v1: enabled by default */
    static const int SCANNER_NO_USAGE=0x02;		/* v1: do not show scanner in usage */
    static const int SCANNER_NO_ALL  =0x04;		// v2: do not enable with -eALL
    static const int CURRENT_SI_VERSION=1;

    scanner_info():si_version(CURRENT_SI_VERSION),
		   name(),author(),description(),url(),scanner_version(),
		   flags(0),feature_names(),
		    histogram_defs(){}
    int		si_version;		// version number for this structure
    string	name;			// v1: scanner name
    string	author;			// v1: who wrote me?
    string	description;		// v1: what do I do?
    string	url;			// v1: where I come from
    string	scanner_version;	// v1: version for the scanner
    uint64_t	flags;			// v1: flags
    set<string> feature_names;		// v1: features I need
    histograms_t histogram_defs;	// v1: histogram definition info
};

#include <map>
class scanner_params {
 public:
    /** Construct a scanner_params from a sbuf and other sensible defaults.
     *
     */
    enum print_mode_t {MODE_NONE=0,MODE_HEX,MODE_RAW,MODE_HTTP};
    static const int CURRENT_SP_VERSION=2;

    //typedef tr1::unordered_map<string,string> PrintOptions;
    typedef std::map<string,string> PrintOptions;
    static print_mode_t getPrintMode(const PrintOptions &po){
	PrintOptions::const_iterator p = po.find("print_mode_t");
	if(p != po.end()){
	    if(p->second=="MODE_NONE") return MODE_NONE;
	    if(p->second=="MODE_HEX") return MODE_HEX;
	    if(p->second=="MODE_RAW") return MODE_RAW;
	    if(p->second=="MODE_HTTP") return MODE_HTTP;
	}
	return MODE_NONE;
    }
    static void setPrintMode(PrintOptions &po,int mode){
	switch(mode){
	default:
	case MODE_NONE:po["print_mode_t"]="MODE_NONE";return;
	case MODE_HEX:po["print_mode_t"]="MODE_HEX";return;
	case MODE_RAW:po["print_mode_t"]="MODE_RAW";return;
	case MODE_HTTP:po["print_mode_t"]="MODE_HTTP";return;
	}
    }

    typedef enum {none=-1,startup=0,scan=1,shutdown=2} phase_t ;
    static PrintOptions no_options;	// in common.cpp

    /********************
     *** CONSTRUCTORS ***
     ********************/

    /* A scanner params with all of the instance variables */
    scanner_params(phase_t phase_,const sbuf_t &sbuf_,class feature_recorder_set &fs_,
		   PrintOptions &print_options_):
	sp_version(CURRENT_SP_VERSION),
	phase(phase_),sbuf(sbuf_),fs(fs_),depth(0),
	print_options(print_options_),info(0){
    }

    /* A scanner params with no print options*/
    scanner_params(phase_t phase_,const sbuf_t &sbuf_,class feature_recorder_set &fs_):
	sp_version(CURRENT_SP_VERSION),
	phase(phase_),sbuf(sbuf_),fs(fs_),depth(0),
	print_options(no_options),info(0){
    }

    /** Construct a scanner_params for recursion from an existing sp and a new sbuf.
     * Defaults to phase1
     */
    scanner_params(const scanner_params &sp_existing,const sbuf_t &sbuf_new):
	sp_version(CURRENT_SP_VERSION),phase(sp_existing.phase),
	sbuf(sbuf_new),fs(sp_existing.fs),depth(sp_existing.depth+1),
	print_options(sp_existing.print_options),info(0){
	assert(sp_existing.sp_version==CURRENT_SP_VERSION);
    };

    /**************************
     *** INSTANCE VARIABLES ***
     **************************/

    int      sp_version;		/* version number of this structure */
    phase_t  phase;			/* v1: 0=startup, 1=normal, 2=shutdown (changed to phase_t in v1.3) */
    const sbuf_t &sbuf;			/* v1: what to scan */
    class feature_recorder_set &fs;	/* v1: where to put the results*/
    uint32_t   depth;			/* v1: how far down are we? */

    /* These are for printing */
    PrintOptions  &print_options;	/* v1: how to print */
    scanner_info  *info;		/* v1: get parameters on startup; info's are stored in a the scanner_def vector */
};


inline std::ostream & operator <<(std::ostream &os,const class scanner_params &sp){
    os << "scanner_params(" << sp.sbuf << ")";
    return os;
};

class recursion_control_block {
 public:
/**
 * @param callback_ - the function to call back
 * @param partName_ - the part of the forensic path processed by this scanner.
 * @param raf       - return after free -- don't call *callback_
 */
 recursion_control_block(process_t *callback_,string partName_,bool raf):
    callback(callback_),partName(partName_),returnAfterFound(raf){}
    process_t *callback;
    string partName;		/* eg "ZIP", "GZIP" */
    bool returnAfterFound;	/* only run once */
};
    
/* plugin.cpp */
class scanner_def {
public:;
    static uint32_t max_depth;
    scanner_def():scanner(0),enabled(false),info(),pathPrefix(){};
    const scanner_t  *scanner;		// pointer to the primary entry point
    bool	enabled;		// is enabled?
    scanner_info info;
    string	pathPrefix;		/* path prefix for recursive scanners */
};
void load_scanner(const scanner_t &scanner,histograms_t &histograms);
void load_scanners(const scanner_t *scanners[],histograms_t &histograms);		// load the scan_ plugins
void load_scanner_directory(const string &dirname,histograms_t &histograms);		// load the scan_ plugins
void disable_all_scanners();
typedef vector<scanner_def *> scanner_vector;
extern scanner_vector current_scanners;				// current scanners
extern histograms_t histograms;
void enable_feature_recorders(feature_file_names_t &feature_file_names);


inline std::string itos(int i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string dtos(double d){ std::stringstream ss; ss << d;return ss.str();}
inline std::string utos(unsigned int i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string utos(uint64_t i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string utos(uint16_t i){ std::stringstream ss; ss << i;return ss.str();}
inline std::string safe_utf16to8(std::wstring s){ // needs to be cleaned up
    std::string utf8_line;
    try {
	utf8::utf16to8(s.begin(),s.end(),back_inserter(utf8_line));
    } catch(utf8::invalid_utf16){
	/* Exception thrown: bad UTF16 encoding */
	utf8_line = "";
    }
    return utf8_line;
}


#ifndef HAVE_ISXDIGIT
inline int isxdigit(int c)
{
    return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');
}
#endif





/* Useful functions for scanners */
#define ONE_HUNDRED_NANO_SEC_TO_SECONDS 10000000
#define SECONDS_BETWEEN_WIN32_EPOCH_AND_UNIX_EPOCH 11644473600LL
/*
 * 11644473600 is the number of seconds between the Win32 epoch
 * and the Unix epoch.
 *
 * http://arstechnica.com/civis/viewtopic.php?f=20&t=111992
 */

inline std::string microsoftDateToISODate(const uint64_t &time)
{
    time_t tmp = (time / ONE_HUNDRED_NANO_SEC_TO_SECONDS) - SECONDS_BETWEEN_WIN32_EPOCH_AND_UNIX_EPOCH;
    
    struct tm time_tm;
    gmtime_r(&tmp, &time_tm);
    char buf[256];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &time_tm); // Zulu time
    return string(buf);
}

#endif
