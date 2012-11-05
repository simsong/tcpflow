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
 * This module defines three classes:
 * class feature_recorder - the individual recorders.
 * class feature_recorder_set - the set of recorders.
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
 
using namespace std;
#include <string>
#include <pthread.h>
#include <stdarg.h>
#include <fstream>
#include <set>

#include "md5.h"
#include "regex.h"

class feature_recorder {
private:
    uint32_t flags;
    bool histogram_enabled;		/* do we automatically histogram? */
    /*** neither copying nor assignment is implemented                         ***
     *** We do this by making them private constructors that throw exceptions. ***/
    class not_impl: public exception {
	virtual const char *what() const throw() {
	    return "copying feature_recorder objects is not implemented.";
	}
    };
    feature_recorder(const feature_recorder &fr):
	flags(0),histogram_enabled(false),
	outdir(),name(),count(0),ios(),Mf(),Mr(),
	stop_list_recorder(0),carved_set(),file_number(0),file_extension(){ throw new not_impl(); }
    const feature_recorder &operator=(const feature_recorder &fr){ throw new not_impl(); }
    /****************************************************************/

public:
    typedef string offset_t;

    /**
     * \name Flags that control scanners
     * @{
     * These flags control scanners.  Set them with set_flag().
     */
    /** Disable this recorder. */
    static const int FLAG_DISABLED=0x01;	
    /** Do not write context. */
    static const int FLAG_NO_CONTEXT=0x02;	
    /** Do not honor the stoplist/alertlist. */
    static const int FLAG_NO_STOPLIST=0x04;	
    /** Do not honor the stoplist/alertlist. */
    static const int FLAG_NO_ALERTLIST=0x04;	
    /**
     * Normally feature recorders automatically quote non-UTF8 characters
     * with \x00 notation and quote "\" as \x5C. Specify FLAG_NO_QUOTE to
     * disable this behavior.
     */
    static const int FLAG_NO_QUOTE=0x08;	// do not escape UTF8 codes

    /**
     * Use this flag the feature recorder is sending UTF-8 XML.
     * non-UTF8 will be quoted but "\" will not be escaped.
     */
    static const int FLAG_XML    = 0x10; // will be sending XML


    /** @} */
    static const int max_histogram_files = 10;	// don't make more than 10 files in low-memory conditions
    static const string histogram_file_header;
    static const string feature_file_header;
    static const string bulk_extractor_version_header;
    static const uint8_t UTF8_BOM[3];	// UTF-8 byte order mark
    static const string BOM_EXPLAINATION; // what is this BOM thing? Put at the top of each file
    static uint32_t opt_max_context_size;
    static uint32_t opt_max_feature_size;
    static size_t context_window;	// global option
    static int64_t offset_add;		// added to every reported offset, for use with hadoop
    static string banner_file;		// banner for top of every file
    static string extract_feature(const string &line);

    feature_recorder(string outdir,string name);
    virtual ~feature_recorder();

    void set_flag(uint32_t flags_){flags|=flags_;}

    string outdir;			// where output goes (could be static, I guess 
    string name;			/* name of this feature recorder */
    int64_t count;			/* number of records written */
    std::fstream ios;			/* where features are written */
    cppmutex Mf;			/* protects the file */
    cppmutex Mr;			/* protects the redlist */

    void   banner_stamp(std::ostream &os,const std::string &header); // stamp BOM, banner, and header

    /* where stopped items (on stop_list or context_stop_list) get recorded: */
    class feature_recorder *stop_list_recorder; // where stopped features get written
    string fname_counter(string suffix);
    string quote_string(const string &feature); // turns unprintable characters to octal escape
    static string unquote_string(const string &feature); // turns octal escape back to binary characters

    /* feature file management */
    void open();
    void close();			
    void flush();
    void make_histogram(const class histogram_def &def);
    
    /* Methods to write.
     * write() is the basic write - you say where, and it does it.
     * write_buf() writes from a position within the buffer, with context.
     *             It won't write a feature that starts in the margin.
     * pos0 gives the location and prefix for the beginning of the buffer
     */ 

    /**
     * write() actually does the writing to the file.
     * It uses locks and is threadsafe.
     * Callers therefore do not need locks.
     */
    void write(const std::string &str);

    /**
     * support for writing features
     */

    // only virtual functions may be called by plug-ins
    // printf() prints to the feature file.
    virtual void printf(const char *fmt_,...) __attribute__((format(printf, 2, 3)));
    // 
    // write a feature and its context; the feature may be in the context, but doesn't need to be.
    virtual void write(const pos0_t &pos0,const string &feature,const string &context);  

    // write a feature located at a given place within an sbuf.
    // Context is written automatically
    virtual void write_buf(const sbuf_t &sbuf,size_t pos,size_t len); /* writes with context */

    /**
     * support for carving.
     * Carving writes the filename to the feature file; the context is the file's MD5
     * Automatically de-duplicates.
     */
    std::set<md5_t>	carved_set;		/* set of MD5 hash codes of objects we've carved;  */
    int64_t	file_number;		/* starts at 0; gets incremented by carve() */
    string	file_extension;		/* includes "."; must be set by caller */
    virtual void carve(const sbuf_t &sbuf,size_t pos,size_t len);

    /**
     * support for tagging blocks with their type.
     * typically 'len' is the sector size, but it need not be.
     */
    virtual void write_tag(const pos0_t &pos0,size_t len,const string &tagName);
    virtual void write_tag(const sbuf_t &sbuf,const string &tagName){
	write_tag(sbuf.pos0,sbuf.pagesize,tagName);
    }

};

/** @} */

#endif
