/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "config.h"
#include "bulk_extractor_i.h"
#include "unicode_escape.h"
#include "histogram.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 65536
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef DEBUG_PEDANTIC
#define DEBUG_PEDANTIC    0x0001// check values more rigorously
#endif

#ifndef WIN32
pthread_t feature_recorder::main_threadid = 0;
#endif
size_t  feature_recorder::context_window_default=16;                    /* number of bytes of context */
int64_t feature_recorder::offset_add   = 0;
std::string  feature_recorder::banner_file;
uint32_t feature_recorder::opt_max_context_size=1024*1024;
uint32_t feature_recorder::opt_max_feature_size=1024*1024;
uint32_t feature_recorder::debug=0;


/**
 * Create a feature recorder object. Each recorder records a certain
 * kind of feature.  Features are stored in a file. The filename is
 * permutated based on the total number of threads and the current
 * thread that's recording. Each thread records to a different file,
 * and thus a different feature recorder, to avoid locking
 * problems. 
 *
 * @param feature_recorder_set &fs - common information for all of the feature recorders
 * @param name         - the name of the feature being recorded.
 */

feature_recorder::feature_recorder(class feature_recorder_set &fs_,
                                   const std::string &name_):
    flags(0),
    name(name_),ignore_encoding(),ios(),bs(),
    histogram_defs(),
    fs(fs_),
    count_(0),context_window_before(context_window_default),context_window_after(context_window_default),
    Mf(),Mr(),mhistograms(),mhistogram_limit(),
    stop_list_recorder(0),
    file_number_(0),carve_cache(),carve_mode(CARVE_ENCODED)
{
    //std::cerr << "feature_recorder(" << name << ") created\n";
    open();                         // open if we are created
}

/* Don't have to delete the stop_list_recorder because it is in the
 * feature_recorder_set and will be separately deleted.
 */
feature_recorder::~feature_recorder()
{
    if(ios.is_open()){
        ios.close();
    }
}

void feature_recorder::banner_stamp(std::ostream &os,const std::string &header) const
{
    int banner_lines = 0;
    if(banner_file.size()>0){
        std::ifstream i(banner_file.c_str());
        if(i.is_open()){
            std::string line;
            while(getline(i,line)){
                if(line.size()>0 && ((*line.end()=='\r') || (*line.end()=='\n'))){
                    line.erase(line.end()); /* remove the last character while it is a \n or \r */
                }
                os << "# " << line << "\n";
                banner_lines++;
            }
            i.close();
        }
    }
    if(banner_lines==0){
        os << "# BANNER FILE NOT PROVIDED (-b option)\n";
    }
    
    os << bulk_extractor_version_header;
    os << "# Feature-Recorder: " << name << "\n";
    if(fs.get_input_fname().size()) os << "# Filename: " << fs.get_input_fname() << "\n";
    if(debug!=0){
        os << "# DEBUG: " << debug << " (";
        if(debug & DEBUG_PEDANTIC) os << " DEBUG_PEDANTIC ";
        os << ")\n";
    }
    os << header;
}



/**
 * Return the filename with a counter
 */
std::string feature_recorder::fname_counter(std::string suffix) const
{
    return fs.get_outdir() + "/" + this->name + (suffix.size()>0 ? (std::string("_") + suffix) : "") + ".txt";
}


const std::string &feature_recorder::get_outdir() const 
{
    return fs.get_outdir();
}

/**
 * open a feature recorder file in the specified output directory.
 * Called by create_name(). Not clear why it isn't called when created.
 */

void feature_recorder::open()
{ 
    if (fs.flag_set(feature_recorder_set::SET_DISABLED)) return;        // feature recorder set is disabled

    /* write to a database? Create tables if necessary and create a prepared statement */
    if (fs.flag_set(feature_recorder_set::ENABLE_SQLITE3_RECORDERS)) {  
        char buf[1024];
        fs.db_create_table(name);
        snprintf(buf,sizeof(buf),db_insert_stmt,name.c_str());
        bs = new besql_stmt(fs.db3,buf);
    }

    /* Write to a file? Open the file and seek to the last line if it exist, otherwise just open database */
    if (fs.flag_notset(feature_recorder_set::DISABLE_FILE_RECORDERS)){
        /* Open the file recorder */
        std::string fname = fname_counter("");
        ios.open(fname.c_str(),std::ios_base::in|std::ios_base::out|std::ios_base::ate);
        if(ios.is_open()){                  // opened existing stream
            ios.seekg(0L,std::ios_base::end);
            while(ios.is_open()){
                /* Get current position */
                if(int(ios.tellg())==0){            // at beginning of file; stamp and return
                    ios.seekp(0L,std::ios_base::beg);    // be sure we are at the beginning of the file
                    return;
                }
                ios.seekg(-1,std::ios_base::cur); // backup to once less than the end of the file
                if (ios.peek()=='\n'){           // we are finally on the \n
                    ios.seekg(1L,std::ios_base::cur); // move the getting one forward
                    ios.seekp(ios.tellg(),std::ios_base::beg); // put the putter at the getter location
                    count_ = 1;                            // greater than zero
                    return;
                }
            }
        }
        // Just open the stream for output
        ios.open(fname.c_str(),std::ios_base::out);
        if(!ios.is_open()){
            std::cerr << "*** feature_recorder::open CANNOT OPEN FEATURE FILE FOR WRITING "
                      << fname << ":" << strerror(errno) << "\n";
            exit(1);
        }
    }
}

void feature_recorder::close()
{
    if(ios.is_open()){
        ios.close();
    }
}

void feature_recorder::flush()
{
    cppmutex::lock lock(Mf);            // get the lock; released when object is deallocated.
    ios.flush();
}


static inline bool isodigit(char c)
{
    return c>='0' && c<='7';
}

/* statics */
const std::string feature_recorder::feature_file_header("# Feature-File-Version: 1.1\n");
const std::string feature_recorder::histogram_file_header("# Histogram-File-Version: 1.1\n");
const std::string feature_recorder::bulk_extractor_version_header("# " PACKAGE_NAME "-Version: " PACKAGE_VERSION " ($Rev: 10844 $)\n");

static inline int hexval(char ch)
{
    switch (ch) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    }
    return 0;
}

/**
 * Unquote Python or octal-style quoting of a string
 */
std::string feature_recorder::unquote_string(const std::string &s)
{
    size_t len = s.size();
    if(len<4) return s;                 // too small for a quote

    std::string out;
    for(size_t i=0;i<len;i++){
        /* Look for octal coding */
        if(i+3<len && s[i]=='\\' && isodigit(s[i+1]) && isodigit(s[i+2]) && isodigit(s[i+3])){
            uint8_t code = (s[i+1]-'0') * 64 + (s[i+2]-'0') * 8 + (s[i+3]-'0');
            out.push_back(code);
            i += 3;                     // skip over the digits
            continue;
        }
        /* Look for hex coding */
        if(i+3<len && s[i]=='\\' && s[i+1]=='x' && isxdigit(s[i+2]) && isxdigit(s[i+3])){
            uint8_t code = (hexval(s[i+2])*16) | hexval(s[i+3]);
            out.push_back(code);
            i += 3;                     // skip over the digits
            continue;
        }
        out.push_back(s[i]);
    }
    return out;
}

/**
 * Get the feature which is defined as being between a \t and [\t\n]
 */

/*static*/ std::string feature_recorder::extract_feature(const std::string &line)
{
    size_t tab1 = line.find('\t');
    if(tab1==std::string::npos) return "";   // no feature
    size_t feature_start = tab1+1;
    size_t tab2 = line.find('\t',feature_start);
    if(tab2!=std::string::npos) return line.substr(feature_start,tab2-feature_start);
    return line.substr(feature_start);  // no context to remove
}

void feature_recorder::set_flag(uint32_t flags_)
{
    MAINTHREAD();
    flags|=flags_;
}

void feature_recorder::unset_flag(uint32_t flags_)
{
    MAINTHREAD();
    flags &= (~flags_);
}

void feature_recorder::set_memhist_limit(int64_t limit_)
{
    MAINTHREAD();
    mhistogram_limit = limit_;
}


// add a memory histogram; assume the position in the mhistograms is stable
void feature_recorder::enable_memory_histograms()
{
    for(histogram_defs_t::const_iterator it=histogram_defs.begin();it!=histogram_defs.end();it++){
        mhistograms[*it] = new mhistogram_t(); 
    }
}


/**
 *  Create a histogram for this feature recorder and an extraction pattern.
 */

/* dump_callback_test is a simple callback that just prints to stderr. It's for testing */
int feature_recorder::dump_callback_test(void *user,const feature_recorder &fr,
                                          const std::string &str,const uint64_t &count)
{
    (void)user;
    std::cerr << "dump_cb: user=" << user << " " << str << ": " << count << "\n";
    return 0;
}

/* Make a histogram. If a callback is provided, send the output there. */
class mhistogram_callback {
    mhistogram_callback(const mhistogram_callback&);
    mhistogram_callback &operator=(const mhistogram_callback &);
public:
    mhistogram_callback(void *user_,
                        feature_recorder::dump_callback_t *cb_,
                        const histogram_def &def_,
                        const feature_recorder &fr_,
                        uint64_t limit_):user(user_),cb(cb_),def(def_),fr(fr_),callback_count(0),limit(limit_){}
    void *user;
    feature_recorder::dump_callback_t *cb;
    const histogram_def &def;
    const feature_recorder &fr;
    uint64_t callback_count;
    uint64_t limit;
    int do_callback(const std::string &str,const uint64_t &tally){
        (*cb)(user,fr,def,str,tally);
        if(limit && ++callback_count >= limit) return -1;
        return 0;
    }
    static int callback(void *ptr,const std::string &str,const uint64_t &tally) {
        return ((mhistogram_callback *)(ptr))->do_callback(str,tally);
    }
};

/****************************************************************
 *** PHASE HISTOGRAM (formerly phase 3): Create the histograms
 ****************************************************************/

/**
 * We now have three kinds of histograms:
 * 1 - Traditional post-processing histograms specified by the histogram library
 *   1a - feature-file based traditional ones
 *   1b - SQL-based traditional ones.
 * 2 - In-memory histograms (used primarily by beapi)
 */


/** Dump a specific histogram */
void feature_recorder::dump_histogram_file(const histogram_def &def,void *user,feature_recorder::dump_callback_t cb) const
{
    /* This is a file based histogram. We will be reading from one file and writing to another */
    std::string ifname = fname_counter("");  // source of features
    std::ifstream f(ifname.c_str());
    if(!f.is_open()){
        std::cerr << "Cannot open histogram input file: " << ifname << "\n";
        return;
    }

    /* Read each line of the feature file and add it to the histogram.
     * If we run out of memory, dump that histogram to a file and start
     * on the next histogram.
     */
    for(int histogram_counter = 0;histogram_counter<max_histogram_files;histogram_counter++){

        HistogramMaker h(def.flags);            /* of seen features, created in pass two */
        try {
            std::string line;
            while(getline(f,line)){
                if(line.size()==0) continue; // empty line
                if(line[0]=='#') continue;   // comment line
                truncate_at(line,'\r');      // truncate at a \r if there is one.

                /** If there is a string required in the line and it isn't present, don't use this line */
                if(def.require.size()){
                    if(line.find_first_of(def.require)==std::string::npos){
                        continue;
                    }
                }

                std::string feature = extract_feature(line);
                if(feature.find('\\')!=std::string::npos){
                    feature = unquote_string(feature);  // reverse \xxx encoding
                }
                /** If there is a pattern to use to prune down the feature, use it */
                if(def.pattern.size()){
                    std::string new_feature = feature;
                    if(!def.reg.search(feature,&new_feature,0,0)){
                        // no search match; avoid this feature
                        continue;               
                    }
                    feature = new_feature;
                }
        
                /* Remove what follows after \t if this is a context file */
                size_t tab=feature.find('\t');
                if(tab!=std::string::npos) feature.erase(tab); // erase from tab to end
                h.add(feature);
            }
            f.close();
        }
        catch (const std::exception &e) {
            std::cerr << "ERROR: " << e.what() << " generating histogram "
                      << name << "\n";
        }
            
        /* Output what we have to a new file ofname */
        std::stringstream real_suffix;

        real_suffix << def.suffix;
        if(histogram_counter>0) real_suffix << histogram_counter;
        std::string ofname = fname_counter(real_suffix.str()); // histogram name
        std::ofstream o;
        o.open(ofname.c_str());         // open the file
        if(!o.is_open()){
            std::cerr << "Cannot open histogram output file: " << ofname << "\n";
            return;
        }

        HistogramMaker::FrequencyReportVector *fr = h.makeReport();
        if(fr->size()>0){
            banner_stamp(o,histogram_file_header);
            o << *fr;                   // sends the entire histogram
        }

        for(size_t i = 0;i<fr->size();i++){
            delete fr->at(i);
        }
        delete fr;
        o.close();

        if(f.is_open()==false){
            return;     // input file was closed
        }
    }
    std::cerr << "Looped " << max_histogram_files
              << " times on histogram; something seems wrong\n";
}


void feature_recorder::dump_histogram(const histogram_def &def,void *user,feature_recorder::dump_callback_t cb) const
{
    /* Inform that we are dumping this histogram */
    if(cb) cb(user,*this,def,"",0); 

    /* If this is a memory histogram, dump it and return */
    mhistograms_t::const_iterator it = mhistograms.find(def);
    if(it!=mhistograms.end()){
        assert(cb!=0);
        mhistogram_callback mcbo(user,cb,def,*this,mhistogram_limit);
        it->second->dump_sorted(static_cast<void *>(&mcbo),mhistogram_callback::callback);
        return;
    }

    if (fs.flag_set(feature_recorder_set::ENABLE_SQLITE3_RECORDERS)) {
        dump_histogram_db(def,user,cb);
    }
    

    if (fs.flag_notset(feature_recorder_set::DISABLE_FILE_RECORDERS)) {
        dump_histogram_file(def,user,cb);
    }
}


/* Dump all of this feature recorders histograms */


void feature_recorder::dump_histograms(void *user,feature_recorder::dump_callback_t cb,
                                           feature_recorder_set::xml_notifier_t xml_error_notifier) const
{
    /* If we are recording features to SQL and we have a histogram defintion
     * for this feature recorder, we need to create a base histogram first,
     * then we can create the extracted histograms if they are presented.
     */


    /* Loop through all the histograms and dump each one.
     * This now works for both memory histograms and non-memory histograms.
     */
    for(histogram_defs_t::const_iterator it = histogram_defs.begin();it!=histogram_defs.end();it++){
        try {
            dump_histogram((*it),user,cb);
        }
        catch (const std::exception &e) {
            std::cerr << "ERROR: histogram " << name << ": " << e.what() << "\n";
            if(xml_error_notifier){
                std::string error = std::string("<error function='phase3' histogram='")
                    + name + std::string("</error>");
                (*xml_error_notifier)(error);
            }
        }
    }
}


void feature_recorder::add_histogram(const histogram_def &def)
{
    histogram_defs.insert(def);
}



/****************************************************************
 *** WRITING SUPPORT
 ****************************************************************/

/* Write to the file.
 * This is the only place where writing happens.
 * So it's an easy place to do UTF-8 validation in debug mode.
 */
void feature_recorder::write(const std::string &str)
{
    if(debug & DEBUG_PEDANTIC){
        if(utf8::find_invalid(str.begin(),str.end()) != str.end()){
            std::cerr << "******************************************\n";
            std::cerr << "feature recorder: " << name << "\n";
            std::cerr << "invalid UTF-8 in write: " << str << "\n";
            assert(0);
        }
    }

    /* This is where the writing happens. Lock the output and write */
    if (fs.flag_set(feature_recorder_set::DISABLE_FILE_RECORDERS)) {
        return;
    }

    cppmutex::lock lock(Mf);
    if(ios.is_open()){
        if(count_==0){
            banner_stamp(ios,feature_file_header);
        }

        ios << str << '\n';
        if(ios.fail()){
            std::cerr << "DISK FULL\n";
            ios.close();
        }
        count_++;
    }
}

void feature_recorder::printf(const char *fmt, ...)
{
    const int maxsize = 65536;
    managed_malloc<char>p(maxsize);
    
    if(p.buf==0) return;

    va_list ap;
    va_start(ap,fmt);
    vsnprintf(p.buf,maxsize,fmt,ap);
    va_end(ap);
    this->write(p.buf);
}


/**
 * Combine the pos0, feature and context into a single line and write it to the feature file.
 *
 * @param feature - The feature, which is valid UTF8 (but may not be exactly the bytes on the disk)
 * @param context - The context, which is valid UTF8 (but may not be exactly the bytes on the disk)
 *
 * Interlocking is done in write().
 */

void feature_recorder::write0(const pos0_t &pos0,const std::string &feature,const std::string &context)
{
    if ( fs.flag_set(feature_recorder_set::ENABLE_SQLITE3_RECORDERS ) &&
         this->flag_notset(feature_recorder::FLAG_NO_FEATURES_SQL) ) {
        db_write0( pos0, feature, context);
    }
    if ( fs.flag_notset(feature_recorder_set::DISABLE_FILE_RECORDERS )) {
        std::stringstream ss;
        ss << pos0.shift( feature_recorder::offset_add).str() << '\t' << feature;
        if (flag_notset( FLAG_NO_CONTEXT ) && ( context.size()>0 )) ss << '\t' << context;
        this->write( ss.str() );
    }
}


/**
 * the main entry point of writing a feature and its context to the feature file.
 * processes the stop list
 */

void feature_recorder::quote_if_necessary(std::string &feature,std::string &context)
{
    /* By default quote string that is not UTF-8, and quote backslashes. */
    bool escape_bad_utf8  = true;
    bool escape_backslash = true;

    if(flags & FLAG_NO_QUOTE){          // don't quote either
        escape_bad_utf8  = false;
        escape_backslash = false;
    }

    if(flags & FLAG_XML){               // only quote bad utf8
        escape_bad_utf8  = true;
        escape_backslash = false;
    }

    feature = validateOrEscapeUTF8(feature, escape_bad_utf8,escape_backslash);
    if(feature.size() > opt_max_feature_size) feature.resize(opt_max_feature_size);
    if(flag_notset(FLAG_NO_CONTEXT)){
        context = validateOrEscapeUTF8(context,escape_bad_utf8,escape_backslash);
        if(context.size() > opt_max_context_size) context.resize(opt_max_context_size);
    }
}

/**
 * write() is the main entry point for writing a feature at a given position with context.
 * write() checks the stoplist and escapes non-UTF8 characters, then calls write0().
 */
void feature_recorder::write(const pos0_t &pos0,const std::string &feature_,const std::string &context_)
{
    if(flags & FLAG_DISABLED) return;           // disabled
    if(debug & DEBUG_PEDANTIC){
        if(feature_.size() > opt_max_feature_size){
            std::cerr << "feature_recorder::write : feature_.size()=" << feature_.size() << "\n";
            assert(0);
        }
        if(context_.size() > opt_max_context_size){
            std::cerr << "feature_recorder::write : context_.size()=" << context_.size() << "\n";
            assert(0);
        }
    }

    std::string feature = feature_;
    std::string context = flag_set(FLAG_NO_CONTEXT) ? "" : context_;
    std::string *feature_utf8 = HistogramMaker::make_utf8(feature); // a utf8 feature

    quote_if_necessary(feature,context);

    if(feature.size()==0){
        std::cerr << name << ": zero length feature at " << pos0 << "\n";
        if(debug & DEBUG_PEDANTIC) assert(0);
        return;
    }
    if(debug & DEBUG_PEDANTIC){
        /* Check for tabs or newlines in feature and and context */
        for(size_t i=0;i<feature.size();i++){
            if(feature[i]=='\t') assert(0);
            if(feature[i]=='\n') assert(0);
            if(feature[i]=='\r') assert(0);
        }
        for(size_t i=0;i<context.size();i++){
            if(context[i]=='\t') assert(0);
            if(context[i]=='\n') assert(0);
            if(context[i]=='\r') assert(0);
        }
    }
        
    /* First check to see if the feature is on the stop list.
     * Only do this if we have a stop_list_recorder (the stop list recorder itself
     * does not have a stop list recorder. If it did we would infinitely recurse.
     */
    if(flag_notset(FLAG_NO_STOPLIST) && stop_list_recorder){          
        if(fs.stop_list
           && fs.stop_list->check_feature_context(*feature_utf8,context)){
            stop_list_recorder->write(pos0,feature,context);
            delete feature_utf8;
            return;
        }
    }

    /* The alert list is a special features that are called out.
     * If we have one of those, write it to the redlist.
     */
    if(flag_notset(FLAG_NO_ALERTLIST)
       && fs.alert_list
       && fs.alert_list->check_feature_context(*feature_utf8,context)){
        std::string alert_fn = fs.get_outdir() + "/ALERTS_found.txt";
        cppmutex::lock lock(Mr);                // notice we are locking the alert list
        std::ofstream rf(alert_fn.c_str(),std::ios_base::app);
        if(rf.is_open()){
            rf << pos0.shift(feature_recorder::offset_add).str() << '\t' << feature << '\t' << "\n";
        }
    }

    /* Support in-memory histograms */
    for(mhistograms_t::iterator it = mhistograms.begin(); it!=mhistograms.end();it++){
        const histogram_def &def = it->first;
        mhistogram_t *m = it->second;
        std::string new_feature = *feature_utf8;
        if(def.require.size()==0 || new_feature.find_first_of(def.require)!=std::string::npos){
            /* If there is a pattern to use, use it */
            if(def.pattern.size()){
                if(!def.reg.search(new_feature,&new_feature,0,0)){
                    // no search match; avoid this feature
                    new_feature = "";
                }
            }
            if(new_feature.size()) m->add(new_feature,1);
        }
    }

    /* Finally write out the feature and the context */
    if(flag_notset(FLAG_NO_FEATURES)){
        this->write0(pos0,feature,context);
    }
    delete feature_utf8;
}

/**
 * Given a buffer, an offset into that buffer of the feature, and the length
 * of the feature, make the context and write it out. This is mostly used
 * for writing from within the lexical analyzers.
 */

void feature_recorder::write_buf(const sbuf_t &sbuf,size_t pos,size_t len)
{
#ifdef DEBUG_SCANNER
    if(debug & DEBUG_SCANNER){
        std::cerr << "*** write_buf " << name << " sbuf=" << sbuf << " pos=" << pos << " len=" << len << "\n";
        // for debugging, print Imagine that when pos= the location where the crash is happening.
        // then set a breakpoint at std::cerr.
        if(pos==9999999){
            std::cerr << "Imagine that\n";
        }
    }
#endif

    /* If we are in the margin, ignore; it will be processed again */
    if(pos >= sbuf.pagesize && pos < sbuf.bufsize){
        return;
    }

    if(pos >= sbuf.bufsize){    /* Sanity checks */
        std::cerr << "*** write_buf: WRITE OUTSIDE BUFFER. "
                  << " pos="  << pos
                  << " sbuf=" << sbuf << "\n";
        return;
    }

    /* Asked to write beyond bufsize; bring it in */
    if(pos+len > sbuf.bufsize){
        len = sbuf.bufsize - pos;
    }

    std::string feature = sbuf.substr(pos,len);
    std::string context;

    if((flags & FLAG_NO_CONTEXT)==0){
        /* Context write; create a clean context */
        size_t p0 = context_window_before < pos ? pos-context_window_before : 0;
        size_t p1 = pos+len+context_window_after;
        
        if(p1>sbuf.bufsize) p1 = sbuf.bufsize;
        assert(p0<=p1);
        context = sbuf.substr(p0,p1-p0);
    }
    this->write(sbuf.pos0+pos,feature,context);
#ifdef DEBUG_SCANNER
    if(debug & DEBUG_SCANNER){
        std::cerr << ".\n";
    }
#endif
}


/**
 * replace a character in a string with another
 */
std::string replace(const std::string &src,char f,char t)
{
    std::string ret;
    for(size_t i=0;i<src.size();i++){
        if(src[i]==f) ret.push_back(t);
        else ret.push_back(src[i]);
    }
    return ret;
}

/****************************************************************
 *** CARVING SUPPORT
 ****************************************************************
 *
 * Carving support.
 * 2014-04-24 - $ is no longer valid either
 * 2013-08-29 - replace invalid characters in filenames
 * 2013-07-30 - automatically bin directories
 * 2013-06-08 - filenames are the forensic path.
 */

std::string valid_dosname(std::string in)
{
    std::string out;
    for(size_t i=0;i<in.size();i++){
        uint8_t ch = in.at(i);
        if(ch<=32 || ch>=128
           || ch=='"' || ch=='*' || ch=='+' || ch==','
           || ch=='/' || ch==':' || ch==';' || ch=='<'
           || ch=='=' || ch=='>' || ch=='?' || ch=='\\'
           || ch=='[' || ch==']' || ch=='|' || ch=='$' ){
            out.push_back('_');
        } else {
            out.push_back(ch);
        }
    }
    return out;
}
        

//const feature_recorder::hash_def &feature_recorder::hasher()
//{
//    return fs.hasher;
//}



#include <iomanip>
/**
 * @param sbuf   - the buffer to carve
 * @param pos    - offset in the buffer to carve
 * @param len    - how many bytes to carve
 *
 */
std::string feature_recorder::carve(const sbuf_t &sbuf,size_t pos,size_t len,
                                    const std::string &ext)
{
    if(flags & FLAG_DISABLED) return std::string();           // disabled

    /* If we are in the margin, ignore; it will be processed again */
    if(pos >= sbuf.pagesize && pos < sbuf.bufsize){
        return std::string();
    }
    assert(pos < sbuf.bufsize);
    


    /* Carve to a file depending on the carving mode.  The purpose
     * of CARVE_ENCODED is to allow us to carve JPEGs when they are
     * embedded in, say, GZIP files, but not carve JPEGs that are
     * bare.  The difficulty arises when you have a tool that can go
     * into, say, ZIP files. In this case, we don't want to carve
     * every ZIP file, just the (for example) XORed ZIP files. So the
     * ZIP carver doesn't carve every ZIP file, just the ZIP files
     * that are in HIBER files.  That is, we want to not carve a path
     * of ZIP-234234 but we do want to carve a path of
     * 1000-HIBER-33423-ZIP-2343.  This is implemented by having an
     * ignore_encoding. the ZIP carver sets it to ZIP so it won't
     * carve things that are just found in a ZIP file. This means that
     * it won't carve disembodied ZIP files found in unallocated
     * space. You might want to do that.  If so, set ZIP's carve mode
     * to CARVE_ALL.
     */
    switch(carve_mode){
    case CARVE_NONE:
        return std::string();                         // carve nothing
    case CARVE_ENCODED:
        if(sbuf.pos0.path.size()==0) return std::string(); // not encoded
        if(sbuf.pos0.alphaPart()==ignore_encoding) return std::string(); // ignore if it is just encoded with this
        break;                                      // otherwise carve
    case CARVE_ALL:
        break;
    }

    /* If the directory doesn't exist, make it.
     * If two threads try to make the directory,
     * that's okay, because the second one will fail.
     */

    sbuf_t cbuf(sbuf,pos,len);          // the buf we are going to carve
    std::string carved_hash_hexvalue = (*fs.hasher.func)(cbuf.buf,cbuf.bufsize);

    /* See if this is in the cache */
    bool in_cache = carve_cache.check_for_presence_and_insert(carved_hash_hexvalue);


    uint64_t this_file_number = file_number_add(in_cache ? 0 : 1); // increment if we are not in the cache
    std::string dirname1 = fs.get_outdir() + "/" + name;

    std::stringstream ss;
    ss << dirname1 << "/" << std::setw(3) << std::setfill('0') << (this_file_number / 1000);

    std::string dirname2 = ss.str(); 
    std::string fname         = dirname2 + std::string("/") + valid_dosname(cbuf.pos0.str() + ext);
    std::string fname_feature = fname.substr(fs.get_outdir().size()+1); 

    /* Record what was found in the feature file.
     */
    if (in_cache){
        fname="";             // no filename
        fname_feature="<CACHED>";
    }

    // write to the feature file
    ss.str(std::string()); // clear the stringstream
    ss << "<fileobject>";
    if (!in_cache) ss << "<filename>" << fname << "</filename>";
    ss << "<filesize>" << len << "</filesize>";
    ss << "<hashdigest type='" << fs.hasher.name << "'>" << carved_hash_hexvalue << "</hashdigest></fileobject>";
    this->write(cbuf.pos0,fname_feature,ss.str());
    
    if (in_cache) return fname;               // do not make directories or write out if we are cached

    /* Make the directory if it doesn't exist.  */
    if (access(dirname2.c_str(),R_OK)!=0){
#ifdef WIN32
        mkdir(dirname1.c_str());
        mkdir(dirname2.c_str());
#else   
        mkdir(dirname1.c_str(),0777);
        mkdir(dirname2.c_str(),0777);
#endif
    }
    /* Check to make sure that directory is there. We don't just the return code
     * because there could have been two attempts to make the directory simultaneously,
     * so the mkdir could fail but the directory could nevertheless exist. We need to
     * remember the error number because the access() call may clear it.
     */
    int oerrno = errno;                 // remember error number
    if (access(dirname2.c_str(),R_OK)!=0){
        std::cerr << "Could not make directory " << dirname2 << ": " << strerror(oerrno) << "\n";
        return std::string();
    }

    /* Write the file into the directory */
    int fd = ::open(fname.c_str(),O_CREAT|O_BINARY|O_RDWR,0666);
    if(fd<0){
        std::cerr << "*** carve: Cannot create " << fname << ": " << strerror(errno) << "\n";
        return std::string();
    }

    ssize_t ret = cbuf.write(fd,0,len);
    if(ret<0){
        std::cerr << "*** carve: Cannot write(pos=" << fd << "," << pos << " len=" << len << "): "<< strerror(errno) << "\n";
    }
    ::close(fd);
    return fname;
}

/**
 * Currently, we need strptime() and utimes() to set the time.
 */
void feature_recorder::set_carve_mtime(const std::string &fname, const std::string &mtime_iso8601) 
{
    if(flags & FLAG_DISABLED) return;           // disabled
#if defined(HAVE_STRPTIME) && defined(HAVE_UTIMES)
    if(fname.size()){
        struct tm tm;
        if(strptime(mtime_iso8601.c_str(),"%Y-%m-%dT%H:%M:%S",&tm)){
            time_t t = mktime(&tm);
            if(t>0){
                const struct timeval times[2] = {{t,0},{t,0}};
                utimes(fname.c_str(),times);
            }
        }
    }
#endif
}

