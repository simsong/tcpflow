/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef FEATURE_RECORDER_H
#define FEATURE_RECORDER_H

/**
 * \addtogroup bulk_extractor_APIs
 * @{
 */

/**
 * feature_recorder.h:
 *
 * System for recording features from the scanners into the feature files.
 *
 * There is one feature_recorder per feature file. It is used both to record
 * the features and to perform the histogram calculation.
 * (That should probably be moved to a different class.) It also also previously
 * had the ability to do a merge sort, but we took that out because it was
 * not necessary.
 *
 * The feature recorders can also check the global alert_list to see
 * if the feature should be written to the alert file. It's opened on
 * demand and immediately flushed and closed.  A special mutex is used
 * to protect it.
 *
 * Finally, the feature recorder supports the global stop_list, which
 * is a list of features that are not written to the main file but are
 * written to a stop list.  That is implemented with a second
 * feature_recorder.
 *
 * There is one feature_recorder_set per process.
 * The file assumes that bulk_extractor.h is being included.
 */
 
#include <string>
#include <cstdarg>
#include <fstream>
#include <set>
#include <map>
#include <cassert>
#include <pthread.h>

#ifdef HAVE_SQLITE3_H
#include <sqlite3.h>
#ifndef BEAPI_SQLITE
#  define BEAPI_SQLITE3 sqlite3
#  define BEAPI_SQLITE3_STMT sqlite3_stmt
#endif
#endif

#ifndef BEAPI_SQLITE3
#define BEAPI_SQLITE3      void
#define BEAPI_SQLITE3_STMT void
#endif


#include "cppmutex.h"
#include "dfxml/src/dfxml_writer.h"
#include "dfxml/src/hash_t.h"
#include "atomic_set_map.h"
#include "beregex.h"

/**
 * histogram_def defines the histograms that will be made by a feature recorder.
 * If the mhistogram is set, the histogram is generated when features are recorded
 * and kept in memory. If mhistogram is not set, the histogram is generated when the feature recorder is closed.
 */

struct histogram_def {
    /**
     * @param feature- the feature file to histogram (no .txt)
     * @param re     - the regular expression to extract
     * @param require- require this string on the line (usually in context)
     * @param suffix - the suffix to add to the histogram file after feature name before .txt
     * @param flags  - any flags (see above)
     */

    histogram_def(std::string feature_,std::string re_,std::string suffix_,uint32_t flags_=0):
        feature(feature_),pattern(re_),require(),suffix(suffix_),flags(flags_),reg(pattern,REG_EXTENDED){}
    histogram_def(std::string feature_,std::string re_,std::string require_,std::string suffix_,uint32_t flags_=0):
        feature(feature_),pattern(re_),require(require_),suffix(suffix_),flags(flags_),reg(pattern,REG_EXTENDED){ }
    const std::string feature;      /* feature file name */
    const std::string pattern;      /* extract pattern; "" means use entire feature */
    const std::string require;      /* text required somewhere on the feature line; used for IP histograms */
    const std::string suffix;       /* suffix to append; "" means "histogram" */
    const uint32_t    flags;        // defined in histogram.h
    const beregex     reg;          // regular expression for pattern
};

/* NOTE:
 * 1 - This typedef must remain outside the the feature_recorder due
 *     to historical reasons and cannot be made a vector
 * 2 - Do not make historam_def const!  It breaks some compilers.
 */

typedef  std::set<histogram_def> histogram_defs_t; // a set of histogram definitions


inline bool operator <(const histogram_def &h1,const histogram_def &h2)  {
    if (h1.feature<h2.feature) return true;
    if (h1.feature>h2.feature) return false;
    if (h1.pattern<h2.pattern) return true;
    if (h1.pattern>h2.pattern) return false;
    if (h1.suffix<h2.suffix) return true;
    if (h1.suffix>h2.suffix) return false;
    return false;                       /* equal */
};

inline bool operator !=(const histogram_def &h1,const histogram_def &h2)  {
    return h1.feature!=h2.feature || h1.pattern!=h2.pattern || h1.suffix!=h2.suffix;
};


/* carve object cache */
typedef atomic_set<std::string> carve_cache_t;

/* in-memory histograms */
typedef atomic_histogram<std::string,uint64_t> mhistogram_t;             // memory histogram
typedef std::map<histogram_def,mhistogram_t *> mhistograms_t;


class feature_recorder {
    // default copy construction and assignment are meaningless
    // and not implemented
    feature_recorder(const feature_recorder &);
    feature_recorder &operator=(const feature_recorder &);

    static uint32_t debug;              // are we debugging?
    static pthread_t main_threadid;     // main threads ID
    static void MAINTHREAD();           // called if can only be run in the main thread
    uint32_t flags;                     // flags for this feature recorder
    /****************************************************************/

public:
    class besql_stmt {
        besql_stmt(const besql_stmt &);
        besql_stmt &operator=(const besql_stmt &);
public:
        cppmutex           Mstmt;      // a mutext to protect it
        BEAPI_SQLITE3_STMT *stmt;      // the prepared statement
        besql_stmt(BEAPI_SQLITE3 *db3,const char *sql);
        virtual ~besql_stmt();
        void insert_feature(const pos0_t &pos, // insert it into this table!
                            const std::string &feature,const std::string &feature8, const std::string &context);
    };

    typedef int (dump_callback_t)(void *user,const feature_recorder &fr,const histogram_def &def,
                                  const std::string &feature,const uint64_t &count);
    static void set_main_threadid(){
#ifndef WIN32
        main_threadid=pthread_self();
#endif
    };             // set the main 
    static void set_debug(uint32_t ndebug){debug=ndebug;}
    typedef std::string offset_t;

    /**
     * \name Flags that control scanners
     * @{
     * These flags control scanners.  Set them with set_flag().
     */
    /** Disable this recorder. */
    static const int FLAG_DISABLED         = 0x01;      // feature recorder is Disabled
    static const int FLAG_NO_CONTEXT       = 0x02;      // Do not write context.
    static const int FLAG_NO_STOPLIST      = 0x04;      // Do not honor the stoplist/alertlist.
    static const int FLAG_NO_ALERTLIST     = 0x08;      // Do not honor the stoplist/alertlist.
    /**
     * Normally feature recorders automatically quote non-UTF8 characters
     * with \x00 notation and quote "\" as \x5C. Specify FLAG_NO_QUOTE to
     * disable this behavior.
     */
    static const int FLAG_NO_QUOTE         = 0x10;         // do not escape UTF8 codes

    /**
     * Use this flag the feature recorder is sending UTF-8 XML.
     * non-UTF8 will be quoted but "\" will not be escaped.
     */
    static const int FLAG_XML              = 0x20;         // will be sending XML

    /**
     * histogram support.
     */
    static const uint32_t FLAG_NO_FEATURES = 0x40;  // do not record features (just memory histogram)
    static const uint32_t FLAG_NO_FEATURES_SQL = 0x80;  // do not write features to SQL

    /** @} */
    static const int max_histogram_files = 10;  // don't make more than 10 files in low-memory conditions
    static const std::string histogram_file_header;
    static const std::string feature_file_header;
    static const std::string bulk_extractor_version_header;

    // These must only be changed in the main thread:
    static uint32_t    opt_max_context_size;
    static uint32_t    opt_max_feature_size;
    static int64_t     offset_add;          // added to every reported offset, for use with hadoop
    static std::string banner_file;         // banner for top of every file
    static std::string extract_feature(const std::string &line);

    feature_recorder(class feature_recorder_set &fs,
                     const std::string &name);
    virtual        ~feature_recorder();
    virtual void   set_flag(uint32_t flags_);
    virtual void   unset_flag(uint32_t flags_);
    void           enable_memory_histograms();              // only called from feature_recorder_set
    virtual void   set_memhist_limit(int64_t limit_);
    bool           flag_set(uint32_t f)    const {return flags & f;}
    bool           flag_notset(uint32_t f) const {return !(flags & f);}
    uint32_t       get_flags()             const {return flags;}
    virtual const std::string &get_outdir() const;

    static size_t context_window_default; // global option
    const  std::string name;                  // name of this feature recorder 

private:
    std::string  ignore_encoding;            // encoding to ignore for carving
    std::fstream ios;                        // where features are written 
    
    class besql_stmt *bs;                    // prepared beapi sql statement

protected:;
    histogram_defs_t      histogram_defs;    // histograms that are to be created for this feature recorder
public:
    class        feature_recorder_set &fs;   // the set in which this feature_recorder resides
protected:
    int64_t      count_;                     /* number of records written */
    size_t       context_window_before;      // context window
    size_t       context_window_after;       // context window

    mutable cppmutex Mf;                     // protects the file  & file_number_
    mutable cppmutex Mr;                     // protects the redlist 
    mhistograms_t mhistograms;               // the memory histograms, if we are using them
    uint64_t      mhistogram_limit;          // how many we want (per feature recorder limit, rather than per histogram)

    
    class feature_recorder *stop_list_recorder; // where stopped features get written
    int64_t                file_number_;            /* starts at 0; gets incremented by carve(); */
    carve_cache_t          carve_cache;
public:
    /* these are not threadsafe and should only be called in startup */
    void set_stop_list_recorder(class feature_recorder *fr){
        MAINTHREAD();
        stop_list_recorder = fr;
    }
    void set_context_window(size_t win){
        MAINTHREAD();
        context_window_before = win;
        context_window_after = win;
    }
    void set_context_window_before(size_t win){ MAINTHREAD(); context_window_before = win;}
    void set_context_window_after(size_t win){ MAINTHREAD(); context_window_after = win; }
    void set_carve_ignore_encoding(const std::string &encoding){ MAINTHREAD();ignore_encoding = encoding;}
    /* End non-threadsafe */

    uint64_t file_number_add(uint64_t i){
#ifdef HAVE___SYNC_ADD_AND_FETCH
        return __sync_add_and_fetch(&file_number_,i);
#else
        cppmutex::lock lock(Mf);
        file_number_ += i;
        return file_number_;
#endif
    }

    void   banner_stamp(std::ostream &os,const std::string &header) const; // stamp banner, and header

    /* where stopped items (on stop_list or context_stop_list) get recorded: */
    std::string        fname_counter(std::string suffix) const;
    static std::string quote_string(const std::string &feature); // turns unprintable characters to octal escape
    static std::string unquote_string(const std::string &feature); // turns octal escape back to binary characters

    //virtual const feature_recorder_set::hash_def &hasher();   // returns hasher in feature_recorder_set

    /* feature file management */
    virtual void open();
    virtual void close();                       
    virtual void flush();
    static  int  dump_callback_test(void *user,const feature_recorder &fr,
                                    const std::string &str,const uint64_t &count); // test callback for you to use!
    

    /* TK: The histogram_def should be provided at the beginning, so it can be used for in-memory histograms.
     * The callback needs to have the specific atomic set as the callback as well.
     */
    virtual void add_histogram(const histogram_def &def); // adds a histogram to process
    virtual void dump_histogram_file(const histogram_def &def,void *user,feature_recorder::dump_callback_t cb) const;
    virtual void dump_histogram_db(const histogram_def &def,void *user,feature_recorder::dump_callback_t cb) const;
    virtual void dump_histogram(const histogram_def &def,void *user,feature_recorder::dump_callback_t cb) const;
    typedef void (*xml_notifier_t)(const std::string &xmlstring);
    virtual void dump_histograms(void *user,feature_recorder::dump_callback_t cb, xml_notifier_t xml_error_notifier) const;
    
    /* Methods to get info */
    uint64_t count() const {return count_;}

    /* Methods to write.
     * write() is the basic write - you say where, and it does it.
     * write_buf() writes from a position within the buffer, with context.
     *             It won't write a feature that starts in the margin.
     * pos0 gives the location and prefix for the beginning of the buffer
     */ 


    /****************************************************************
     *** External entry points.
     ****************************************************************/

    /**
     * write() actually does the writing to the file.
     * It uses locks and is threadsafe.
     * Callers therefore do not need locks.
     */
    virtual void write(const std::string &str);

    /**
     * support for writing features
     */

    void quote_if_necessary(std::string &feature,std::string &context);

    // only virtual functions may be called by plug-ins
    // printf() prints to the feature file.
    virtual void printf(const char *fmt_,...) __attribute__((format(printf, 2, 3)));
    // 
    // write a feature and its context; the feature may be in the context, but doesn't need to be.
    // write() calls write0() after histogram, quoting, and stoplist processing
    // write0() calls write0_sql() if sqlwriting is enabled
    virtual void write0(const pos0_t &pos0,const std::string &feature,const std::string &context);  
private:
    virtual void db_write0(const pos0_t &pos0,const std::string &feature,const std::string &context);  
    static const char *db_insert_stmt;
public:

    // write a feature and its context; the feature may be in the context, but doesn't need to be.
    // entries processed by write below will be processed by histogram system
    virtual void write(const pos0_t &pos0,const std::string &feature,const std::string &context);  

    // write a feature located at a given place within an sbuf.
    // Context is written automatically
    virtual void write_buf(const sbuf_t &sbuf,size_t pos,size_t len); /* writes with context */

    /**
     * support for carving.
     * Carving writes the filename to the feature file; the context is the file's hash using the provided function.
     * Automatically de-duplicates.
     */
    enum carve_mode_t {
        CARVE_NONE=0,
        CARVE_ENCODED=1,
        CARVE_ALL=2};
#define CARVE_MODE_DESCRIPTION "0=carve none; 1=carve encoded; 2=carve all"
    carve_mode_t carve_mode;
    typedef      std::string (*hashing_function_t)(const sbuf_t &sbuf); // returns a hex value
    void         set_carve_mode(carve_mode_t aMode){MAINTHREAD();carve_mode=aMode;}

    // Carve a file; returns filename of carved file or empty string if nothing carved
    virtual std::string carve(const sbuf_t &sbuf,size_t pos,size_t len, 
                              const std::string &ext); // appended to forensic path
    // Set the time of the carved file to iso8601 file
    virtual void set_carve_mtime(const std::string &fname, const std::string &mtime_iso8601);
};

// function that can only be called from main thread
inline void feature_recorder::MAINTHREAD()
{
#ifndef WIN32
        assert(main_threadid==pthread_self());
#endif
};                


/** @} */

#endif
