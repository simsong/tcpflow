/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * common.cpp:
 * bulk_extractor backend stuff, used for both standalone executable and bulk_extractor.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>

#ifdef HAVE_ERR_H
#include <err.h>
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include "bulk_extractor_i.h"
#include "aftimer.h"
#include "../dfxml/src/hash_t.h"


uint32_t scanner_def::max_depth = 7;            // max recursion depth
uint32_t scanner_def::max_ngram = 10;            // max recursion depth
static int debug;                               // local debug variable
static uint32_t max_depth_seen=0;
static cppmutex max_depth_seenM;
bool be13::plugin::dup_data_alerts = false; // by default, is disabled
uint64_t be13::plugin::dup_data_encountered = 0; // amount that was not processed

class scanner_command {
public:
    enum command_t {DISABLE_ALL=0,ENABLE_ALL,DISABLE,ENABLE};
    scanner_command(const scanner_command &sc):command(sc.command),name(sc.name){};
    scanner_command(scanner_command::command_t c,const std::string &n):command(c),name(n){};
    command_t command;
    std::string name;
};
static std::vector<scanner_command> scanner_commands;
bool scanner_commands_processed = false;

/****************************************************************
 *** misc support
 ****************************************************************/


/****************************************************************
 *** SCANNER PLUG-IN SYSTEM
 ****************************************************************/

/* scanner_params */

scanner_params::PrintOptions scanner_params::no_options; 

/* vector object for keeping track of packet callbacks */

class packet_plugin_info {
public:
    packet_plugin_info(void *user_,packet_callback_t *callback_):user(user_),callback(callback_){};
    void *user;
    packet_callback_t *callback;
};

typedef std::vector<packet_plugin_info> packet_plugin_info_vector_t;
packet_plugin_info_vector_t  packet_handlers;   // pcap callback handlers


/* plugin */

/**
 * the vector of current scanners
 */

be13::plugin::scanner_vector be13::plugin::current_scanners;  

void be13::plugin::set_scanner_debug(int adebug)
{
    debug = adebug;
}


/**
 * return true a scanner is enabled
 */

/* enable or disable a specific scanner.
 * enable = 0  - disable that scanner.
 * enable = 1  - enable that scanner
 * 'all' is a special scanner that enables all scanners.
 */

void be13::plugin::set_scanner_enabled(const std::string &name,bool enable)
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
    std::cerr << "Invalid scanner name '" << name << "'\n";
    exit(1);
}

void be13::plugin::set_scanner_enabled_all(bool enable)
{
    for(scanner_vector::const_iterator it = current_scanners.begin();it!=current_scanners.end();it++){
        (*it)->enabled = enable;
    }
}

/** Name of feature files that should be histogramed.
 * The histogram should be done in the plug-in
 */

/****************************************************************
 *** scanner plugin loading
 ****************************************************************/

/**
 * plugin system phase 0: Load a scanner.
 *
 * As part of scanner loading:
 * - pass configuration to the scanner
 * - feature files that the scanner requires
 * - Histograms that the scanner makes (see feature_recorder_set)
 * This is called before scanners are enabled or disabled, so the pcap handlers
 * need to be set afterwards
 */
void be13::plugin::load_scanner(scanner_t scanner,const scanner_info::scanner_config &sc)
{
    /* If scanner is already loaded, return */
    for(scanner_vector::const_iterator it = current_scanners.begin();it!=current_scanners.end();it++){
        if((*it)->scanner==scanner) return;
    }

    /* Use an empty sbuf and an empty feature recorder set as the parameters for the sp below.
     * we use static values so that the sbuf is not constantly being created and destroyed.
     */
    static const sbuf_t sbuf;
    static feature_recorder_set fs(feature_recorder_set::SET_DISABLED,feature_recorder_set::null_hasher,
                                   feature_recorder_set::NO_INPUT,
                                   feature_recorder_set::NO_OUTDIR); // dummy

    //
    // Each scanner's params are stored in a scanner_def object that
    // is created here and retained for the duration of the run.
    // The scanner_def includes its own scanner_info structure.
    // We pre-load the structure with the configuration for this scanner
    // and the global debug variable
    //
    // currently every scanner gets the same config. In the future, we might
    // want to give different scanners different variables.
    //

    scanner_params sp(scanner_params::PHASE_STARTUP,sbuf,fs); // 
    scanner_def *sd = new scanner_def();                     
    sd->scanner = scanner;
    sd->info.config = &sc;              

    sp.info  = &sd->info;

    // Make an empty recursion control block and call the scanner's
    // initialization function.
    recursion_control_block rcb(0,""); 
    (*scanner)(sp,rcb);                  // phase 0
    
    sd->enabled      = !(sd->info.flags & scanner_info::SCANNER_DISABLED);
    current_scanners.push_back(sd);
}

void be13::plugin::load_scanner_file(std::string fn,const scanner_info::scanner_config &sc)
{
    /* Figure out the function name */
    size_t extloc = fn.rfind('.');
    if(extloc==std::string::npos){
        fprintf(stderr,"Cannot find '.' in %s",fn.c_str());
        exit(1);
    }
    std::string func_name = fn.substr(0,extloc);
    size_t slashloc = func_name.rfind('/');
    if(slashloc!=std::string::npos) func_name = func_name.substr(slashloc+1);
    slashloc = func_name.rfind('\\');
    if(slashloc!=std::string::npos) func_name = func_name.substr(slashloc+1);

    if(debug) std::cout << "Loading: " << fn << " (" << func_name << ")\n";
    scanner_t *scanner = 0;
#if defined(HAVE_DLOPEN)
    void *lib=dlopen(fn.c_str(), RTLD_LAZY);

    if(lib==0){
        fprintf(stderr,"dlopen: %s\n",dlerror());
        exit(1);
    }

    /* Resolve the symbol */
    scanner = (scanner_t *)dlsym(lib, func_name.c_str());

    if(scanner==0){
        fprintf(stderr,"dlsym: %s\n",dlerror());
        exit(1);
    }
#elif defined(HAVE_LOADLIBRARY)
    /* Use Win32 LoadLibrary function */
    /* See http://msdn.microsoft.com/en-us/library/ms686944(v=vs.85).aspx */
    HINSTANCE hinstLib = LoadLibrary(TEXT(fn.c_str()));
    if(hinstLib==0){
        fprintf(stderr,"LoadLibrary(%s) failed",fn.c_str());
        exit(1);
    }
    scanner = (scanner_t *)GetProcAddress(hinstLib,func_name.c_str());
    if(scanner==0){
        fprintf(stderr,"GetProcAddress(%s) failed",func_name.c_str());
        exit(1);
    }
#else
    std::cout << "  ERROR: Support for loadable libraries not enabled\n";
    return;
#endif
    load_scanner(*scanner,sc);
}

void be13::plugin::load_scanners(scanner_t * const *scanners,const scanner_info::scanner_config &sc)
{
    for(int i=0;scanners[i];i++){
        load_scanner(scanners[i],sc);
    }
}

void be13::plugin::load_scanner_directory(const std::string &dirname,const scanner_info::scanner_config &sc )
{
    DIR *dirp = opendir(dirname.c_str());
    if(dirp==0){
        fprintf(stderr,"Cannot open directory %s:",dirname.c_str());
        exit(1);
    }
    struct dirent *dp;
    while ((dp = readdir(dirp)) != NULL){
        std::string fname = dp->d_name;
        if(fname.substr(0,5)=="scan_" || fname.substr(0,5)=="SCAN_"){
            size_t extloc = fname.rfind('.');
            if(extloc==std::string::npos) continue; // no '.'
            std::string ext = fname.substr(extloc+1);
#ifdef WIN32
            if(ext!="DLL") continue;    // not a DLL
#else
            if(ext!="so") continue;     // not a shared library
#endif
            load_scanner_file(dirname+"/"+fname,sc );
        }
    }
}

void be13::plugin::load_scanner_directories(const std::vector<std::string> &dirnames,
                                            const scanner_info::scanner_config &sc)
{
    for(std::vector<std::string>::const_iterator it = dirnames.begin();it!=dirnames.end();it++){
        load_scanner_directory(*it,sc);
    }
}

void be13::plugin::load_scanner_packet_handlers()
{
    for(scanner_vector::const_iterator it = current_scanners.begin(); it!=current_scanners.end(); it++){
        if((*it)->enabled){
            const scanner_def *sd = (*it);
            if(sd->info.packet_cb){
                packet_handlers.push_back(packet_plugin_info(sd->info.packet_user,sd->info.packet_cb));
            }
        }
    }
}

// send every enabled scanner the phase message
void be13::plugin::message_enabled_scanners(scanner_params::phase_t phase,feature_recorder_set &fs) 
{
    /* make an empty sbuf and feature recorder set */
    const sbuf_t sbuf;
    scanner_params sp(phase,sbuf,fs); 
    for(scanner_vector::iterator it = current_scanners.begin(); it!=current_scanners.end(); it++){
        if((*it)->enabled){
            recursion_control_block rcb(0,""); // dummy rcb
            ((*it)->scanner)(sp,rcb);
        }
    }
}

scanner_t *be13::plugin::find_scanner(const std::string &search_name)
{
    for(scanner_vector::const_iterator it = current_scanners.begin();it!=current_scanners.end();it++){
	if(search_name == (*it)->info.name){
            return (*it)->scanner;
        }
    }
    return 0;
}

// put the enabled scanners into the vector
void be13::plugin::get_enabled_scanners(std::vector<std::string> &svector) 
{
    for(scanner_vector::const_iterator it=current_scanners.begin();it!=current_scanners.end();it++){
	if((*it)->enabled){
            svector.push_back((*it)->info.name);
	}
    }
}

bool be13::plugin::find_scanner_enabled()
{
    for(scanner_vector::const_iterator it = current_scanners.begin(); it!=current_scanners.end(); it++){
        if( ((*it)->info.flags & scanner_info::SCANNER_FIND_SCANNER)
            && ((*it)->enabled)){
            return true;
        }
    }
    return false;
}


void be13::plugin::add_enabled_scanner_histograms_to_feature_recorder_set(feature_recorder_set &fs)
{
    for(scanner_vector::const_iterator it = current_scanners.begin(); it!=current_scanners.end(); it++){
        if((*it)->enabled){
            const scanner_def *sd = (*it);
            for(histogram_defs_t::const_iterator i2 = sd->info.histogram_defs.begin();
                i2 != sd->info.histogram_defs.end(); i2++){
                fs.add_histogram((*i2));
            }
        }
    }
}

void be13::plugin::scanners_init(feature_recorder_set &fs)
{
    assert(scanner_commands_processed==true);
    message_enabled_scanners(scanner_params::PHASE_INIT,fs); // tell all enabled scanners to init
}



/****************************************************************
 *** Scanner Commands (which one is enabled or disabled)
 ****************************************************************/

void be13::plugin::scanners_disable_all()
{
    assert(scanner_commands_processed==false);
    scanner_commands.push_back(scanner_command(scanner_command::DISABLE_ALL,std::string("")));
}

void be13::plugin::scanners_enable_all()
{
    assert(scanner_commands_processed==false);
    scanner_commands.push_back(scanner_command(scanner_command::ENABLE_ALL,std::string("")));
}

void be13::plugin::scanners_enable(const std::string &name)
{
    assert(scanner_commands_processed==false);
    scanner_commands.push_back(scanner_command(scanner_command::ENABLE,name));
}

void be13::plugin::scanners_disable(const std::string &name)
{
    assert(scanner_commands_processed==false);
    scanner_commands.push_back(scanner_command(scanner_command::DISABLE,name));
}

void be13::plugin::scanners_process_enable_disable_commands()
{
    for(std::vector<scanner_command>::const_iterator it=scanner_commands.begin();
        it!=scanner_commands.end();it++){
        switch((*it).command){
        case scanner_command::ENABLE_ALL:  set_scanner_enabled_all(true);break;
        case scanner_command::DISABLE_ALL: set_scanner_enabled_all(false); break;
        case scanner_command::ENABLE:      set_scanner_enabled((*it).name,true);break;
        case scanner_command::DISABLE:     set_scanner_enabled((*it).name,false);break;
        }
    }
    load_scanner_packet_handlers();     // can't do until enable/disable commands are run
    scanner_commands_processed = true;
}


/****************************************************************
 *** PHASE_SHUTDOWN (formerly phase 2): shut down the scanners
 ****************************************************************/

void be13::plugin::phase_shutdown(feature_recorder_set &fs,std::stringstream *sxml)
{
    assert(scanner_commands_processed==true);
    for(scanner_vector::iterator it = current_scanners.begin();it!=current_scanners.end();it++){
        if((*it)->enabled){
            const sbuf_t sbuf; // empty sbuf
            scanner_params sp(scanner_params::PHASE_SHUTDOWN,sbuf,fs,sxml);
            recursion_control_block rcb(0,"");        // empty rcb 
            (*(*it)->scanner)(sp,rcb);
        }
    }
}

/************************************
 *** HELP and  option processing  ***
 ************************************/

/* Get the config and build the help strings at the same time! */

std::stringstream scanner_info::helpstream;
void scanner_info::get_config(const scanner_info::config_t &c,
                              const std::string &n,std::string *val,const std::string &help)
{
    /* Check to see if we are being called as part of a help operation */
    helpstream << "   -S " << n << "=" << *val << "    " << help << " (" << name << ")\n";
    scanner_info::config_t::const_iterator it = c.find(n);
    if(it!=c.end() && val){
        *val = it->second;
    }
}

void scanner_info::get_config(const std::string &n,std::string *val,const std::string &help)
{
    scanner_info::get_config(config->namevals,n,val,help);
}

#define GET_CONFIG(T) void scanner_info::get_config(const std::string &n,T *val,const std::string &help) {\
        std::stringstream ss;\
        ss << *val;\
        std::string v(ss.str());\
        get_config(n,&v,help);\
        ss.str(v);\
        ss >> *val;\
    }

GET_CONFIG(uint64_t)
GET_CONFIG(int32_t)                     // both int32_t and uint32_t
GET_CONFIG(uint32_t)
GET_CONFIG(uint16_t)
#ifdef HAVE_GET_CONFIG_SIZE_T
GET_CONFIG(size_t)
#endif


/* uint8_t needs cast to uint32_t for <<
 * Otherwise it is interpreted as a character.
 */
void scanner_info::get_config(const std::string &n,uint8_t *val_,const std::string &help)
{
    uint32_t val = *val_;
    std::stringstream ss;
    ss << val;
    std::string v(ss.str());
    get_config(n,&v,help);
    ss.str(v);
    ss >> val;
    *val_ = (uint8_t)val;
}

/* bool needs special processing for YES/NO/TRUE/FALSE */
void scanner_info::get_config(const std::string &n,bool *val,const std::string &help)
{
    std::stringstream ss;
    ss << ((*val) ? "YES" : "NO");
    std::string v(ss.str());
    get_config(n,&v,help);
    switch(v.at(0)){
    case 'Y':case 'y':case 'T':case 't':case '1':
        *val = true;
        break;
    default:
        *val = false;
    }
}


/**
 * Print a list of scanners.
 * We need to load them to do this, so they are loaded with empty config
 * Note that scanners can only be loaded once, so this exits.
 */
void be13::plugin::info_scanners(bool detailed_info,
                                 bool detailed_settings,
                                 scanner_t * const *scanners_builtin,
                                 const char enable_opt,const char disable_opt)
{
    const scanner_info::scanner_config empty_config;

    load_scanners(scanners_builtin,empty_config);
    std::cout << "\n";
    std::vector<std::string> enabled_wordlist;
    std::vector<std::string> disabled_wordlist;
    for(scanner_vector::const_iterator it = current_scanners.begin();it!=current_scanners.end();it++){
        if(detailed_info){
            if ((*it)->info.name.size()) std::cout << "Scanner Name: " << (*it)->info.name << "\n";
            std::cout << "flags:  " << scanner_info::flag_to_string((*it)->info.flags) << "\n";
            std::cout << "Scanner Interface version: " << (*it)->info.si_version << "\n";
            if ((*it)->info.author.size()) std::cout << "Author: " << (*it)->info.author << "\n";
            if ((*it)->info.description.size()) std::cout << "Description: " << (*it)->info.description << "\n";
            if ((*it)->info.url.size()) std::cout << "URL: " << (*it)->info.url << "\n";
            if ((*it)->info.scanner_version.size()) std::cout << "Scanner Version: " << (*it)->info.scanner_version << "\n";
            std::cout << "Feature Names: ";
            for(std::set<std::string>::const_iterator i2 = (*it)->info.feature_names.begin();
                i2 != (*it)->info.feature_names.end();
                i2++){
                std::cout << *i2 << " ";
            }
            std::cout << "\n\n";
        }
        if((*it)->info.flags & scanner_info::SCANNER_NO_USAGE) continue;
        if((*it)->info.flags & scanner_info::SCANNER_DISABLED){
            disabled_wordlist.push_back((*it)->info.name);
        } else {
            enabled_wordlist.push_back((*it)->info.name);
        }
    }
    if(detailed_settings){
        std::cout << "Settable Options (and their defaults): \n";
        std::cout << scanner_info::helpstr();
    }
    sort(disabled_wordlist.begin(),disabled_wordlist.end());
    sort(enabled_wordlist.begin(),enabled_wordlist.end());
    std::cout << "\n";
    std::cout << "These scanners disabled by default; enable with -" << enable_opt << ":\n";
    for(std::vector<std::string>::const_iterator it = disabled_wordlist.begin();
        it!=disabled_wordlist.end();it++){
        std::cout << "   -" << enable_opt << " " <<  *it << " - enable scanner " << *it << "\n";
    }
    std::cout << "\n";
    std::cout << "These scanners enabled by default; disable with -" << disable_opt << ":\n";
    for(std::vector<std::string>::const_iterator it = enabled_wordlist.begin();it!=enabled_wordlist.end();it++){
        std::cout << "   -" << disable_opt << " " <<  *it << " - disable scanner " << *it << "\n";
    }
}

/**
 * upperstr - Turns an ASCII string into upper case (should be UTF-8)
 */

static std::string upperstr(const std::string &str)
{
    std::string ret;
    for(std::string::const_iterator i=str.begin();i!=str.end();i++){
        ret.push_back(toupper(*i));
    }
    return ret;
}

/* Determine if the sbuf consists of a repeating ngram */
static size_t find_ngram_size(const sbuf_t &sbuf)
{
    for(size_t ngram_size = 1; ngram_size < scanner_def::max_ngram; ngram_size++){
	bool ngram_match = true;
	for(size_t i=ngram_size;i<sbuf.pagesize && ngram_match;i++){
	    if(sbuf[i%ngram_size]!=sbuf[i]) ngram_match = false;
	}
	if(ngram_match) return ngram_size;
    }
    return 0;                           // no ngram size
}

uint32_t be13::plugin::get_max_depth_seen()
{
    cppmutex::lock lock(max_depth_seenM);
    return max_depth_seen;
}

/** process_sbuf is the main workhorse. It is calls each scanner on each page. 
 * @param sp    - the scanner params, including the sbuf to process 
 * It is also the recursive entry point for sub-analysis.
 */

void be13::plugin::process_sbuf(const class scanner_params &sp)
{
    const pos0_t &pos0 = sp.sbuf.pos0;
    class feature_recorder_set &fs = sp.fs;

    fs.heartbeat();                     // note that we are alive

    {
        /* note the maximum depth that we've seen */
        cppmutex::lock lock(max_depth_seenM);
        if(sp.depth > max_depth_seen) max_depth_seen = sp.depth;
    }

    /* If we are too deep, error out */
    if(sp.depth >= scanner_def::max_depth){
        feature_recorder *fr = fs.get_alert_recorder();
        if(fr) fr->write(pos0,"process_extract: MAX DEPTH REACHED","");
        return;
    }

    /* Determine if we have seen this buffer before */
    bool seen_before = fs.check_previously_processed(sp.sbuf.buf,sp.sbuf.bufsize);
    if(seen_before){
        md5_t md5 = md5_generator::hash_buf(sp.sbuf.buf,sp.sbuf.bufsize);
        feature_recorder *alert_recorder = fs.get_alert_recorder();
        std::stringstream ss;
        ss << "<buflen>" << sp.sbuf.bufsize  << "</buflen>";
        if(alert_recorder && dup_data_alerts) alert_recorder->write(sp.sbuf.pos0,"DUP SBUF "+md5.hexdigest(),ss.str());
#ifdef HAVE__SYNC_ADD_AND_FETCH
        __sync_add_and_fetch(&dup_data_encountered,sp.sbuf.bufsize);
#endif
    }

    /* Determine if the sbuf consists of a repeating ngram. If so,
     * it's only passed to the parsers that want ngrams. (By default,
     * such sbufs are booring.)
     */

    size_t ngram_size = find_ngram_size(sp.sbuf);

    /****************************************************************
     *** CALL EACH OF THE SCANNERS ON THE SBUF
     ****************************************************************/

    if(debug & DEBUG_DUMP_DATA){
        sp.sbuf.hex_dump(std::cerr);
    }

    for(scanner_vector::iterator it = current_scanners.begin();it!=current_scanners.end();it++){
        // Look for reasons not to run a scanner
        if((*it)->enabled==false) continue; // not enabled

        if(((*it)->info.flags & scanner_info::SCANNER_WANTS_NGRAMS)==0){
            /* If the scanner does not want ngrams, don't run it if we have ngrams or duplicate data */
            if(ngram_size > 0) continue;
            if(seen_before)    continue;
        }
        
        if(sp.depth > 0 && ((*it)->info.flags & scanner_info::SCANNER_DEPTH_0)){
            // depth >0 and this scanner only run at depth 0
            continue;
        }

        const std::string &name = (*it)->info.name;

        try {

            /* Compute the effective path for stats */
            bool inname=false;
            std::string epath;
            for(std::string::const_iterator cc=sp.sbuf.pos0.path.begin();cc!=sp.sbuf.pos0.path.end();cc++){
                if(isupper(*cc)) inname=true;
                if(inname) epath.push_back(toupper(*cc));
                if(*cc=='-') inname=false;
            }
            if(epath.size()>0) epath.push_back('-');
            for(std::string::const_iterator cc=name.begin();cc!=name.end();cc++){
                epath.push_back(toupper(*cc));
            }


            /* Create a RCB that will recursively call process_sbuf() */
            recursion_control_block rcb(process_sbuf,upperstr(name));

            /* Call the scanner.*/
            {
                aftimer t;
                if(debug & DEBUG_PRINT_STEPS){
                    std::cerr << "sbuf.pos0=" << sp.sbuf.pos0 << " calling scanner " << name << "\n";
                }
                t.start();
                ((*it)->scanner)(sp,rcb);
                t.stop();
                if(debug & DEBUG_PRINT_STEPS){
                    std::cerr << "sbuf.pos0=" << sp.sbuf.pos0 << " scanner "
                         << name << " t=" << t.elapsed_seconds() << "\n";
                }
                sp.fs.add_stats(epath,t.elapsed_seconds());
            }
                
        }
        catch (const std::exception &e ) {
            std::stringstream ss;
            ss << "std::exception Scanner: " << name
               << " Exception: " << e.what()
               << " sbuf.pos0: " << sp.sbuf.pos0 << " bufsize=" << sp.sbuf.bufsize << "\n";
            std::cerr << ss.str();
            feature_recorder *alert_recorder = fs.get_alert_recorder();
            if(alert_recorder) alert_recorder->write(sp.sbuf.pos0,"scanner="+name,
                                                     std::string("<exception>")+e.what()+"</exception>");
        }
        catch (...) {
            std::stringstream ss;
            ss << "std::exception Scanner: " << name
               << " Unknown Exception " 
               << " sbuf.pos0: " << sp.sbuf.pos0 << " bufsize=" << sp.sbuf.bufsize << "\n";
            std::cerr << ss.str();
            feature_recorder *alert_recorder = fs.get_alert_recorder();
            if(alert_recorder) alert_recorder->write(sp.sbuf.pos0,"scanner="+name,"<unknown_exception/>");
        }
    }
    fs.flush_all();
}



/**
 * Process a pcap packet.
 * Designed to be very efficient because we have so many packets.
 */
void be13::plugin::process_packet(const be13::packet_info &pi)
{
    for(packet_plugin_info_vector_t::iterator it = packet_handlers.begin(); it != packet_handlers.end(); it++){
        (*(*it).callback)((*it).user,pi);
    }
}


void be13::plugin::get_scanner_feature_file_names(feature_file_names_t &feature_file_names)
{
    for(scanner_vector::const_iterator it=current_scanners.begin();it!=current_scanners.end();it++){
        if((*it)->enabled){
            for(std::set<std::string>::const_iterator fi=(*it)->info.feature_names.begin();
                fi!=(*it)->info.feature_names.end();
                fi++){
                feature_file_names.insert(*fi);
            }
        }
    }
}

