/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Simson's XML output class.
 * Include this AFTER your config file with the HAVE statements.
 * Optimized for DFXML generation.
 */

#ifndef _DFXML_WRITER_H_
#define _DFXML_WRITER_H_

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>

/* c++ */
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stack>
#include <string>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#ifndef __BEGIN_DECLS
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#ifdef HAVE_LIBTSK3
#include <tsk3/libtsk.h>
#endif

#ifdef __cplusplus
#include "cppmutex.h"
class dfxml_writer {
private:
    /*** neither copying nor assignment is implemented ***
     *** We do this by making them private constructors that throw exceptions. ***/
    dfxml_writer(const dfxml_writer &);
    dfxml_writer &operator=(const dfxml_writer &);
    /****************************************************************/

public:
    typedef std::map<std::string,std::string> strstrmap_t;
    typedef std::set<std::string> stringset;
    typedef std::set<std::string> tagid_set_t;
private:

#ifdef HAVE_PTHREAD
    pthread_mutex_t M;                  // mutext protecting out
#else
    int M;                              // placeholder
#endif
    std::fstream outf;
    std::ostream *out;                  // where it is being written; defaulst to stdout
    stringset tags;                     // XML tags
    std::stack<std::string>tag_stack;
    std::string  tempfilename;
    std::string  tempfile_template;
    struct timeval t0;
    struct timeval t_last_timestamp;	// for creating delta timestamps
    bool  make_dtd;
    std::string outfilename;
    void  write_doctype(std::fstream &out);
    void  write_dtd();
    void  verify_tag(std::string tag);
    void  spaces();                     // print spaces corresponding to tag stack
    //static std::string xml_PRId32;      // for compiler bug
    //static std::string xml_PRIu32;      // for compiler bug
    //static std::string xml_PRId64;      // for compiler bug
    //static std::string xml_PRIu64;      // for compiler bug
    bool oneline;
public:
    static std::string make_command_line(int argc,char * const *argv){
        std::string command_line;
        for(int i=0;i<argc;i++){
            // append space separator between arguments
            if(i>0) command_line.push_back(' ');
            if (strchr(argv[i],' ') != NULL) {
                // the argument has a space, so quote the argument
                command_line.append("\"");
                command_line.append(argv[i]);
                command_line.append("\"");
            } else {
                // the argument has no space, so append as is
                command_line.append(argv[i]);
            }
        }
        return command_line;
    }


    dfxml_writer();                                       // defaults to stdout
    dfxml_writer(const std::string &outfilename,bool makeDTD); // write to a file, optionally making a DTD
    virtual ~dfxml_writer(){};
    void set_tempfile_template(const std::string &temp);

    static std::string xmlescape(const std::string &xml);
    static std::string xmlstrip(const std::string &xml);

    /** xmlmap turns a map into an XML block */
    static std::string xmlmap(const strstrmap_t &m,const std::string &outer,const std::string &attrs);

    void close();                       // writes the output to the file

    void flush(){outf.flush();}
    void tagout( const std::string &tag,const std::string &attribute);
    void push(const std::string &tag,const std::string &attribute);
    void push(const std::string &tag) {push(tag,"");}

    // writes a std::string as parsed data
    void puts(const std::string &pdata);

    // writes a std::string as parsed data
    void printf(const char *fmt,...) __attribute__((format(printf, 2, 3))); // "2" because this is "1"
    void pop(); // close the tag

    void add_timestamp(const std::string &name);
    void add_DFXML_build_environment();
    static void cpuid(uint32_t op, unsigned long *eax, unsigned long *ebx,unsigned long *ecx, unsigned long *edx);
    void add_cpuid();
    void add_DFXML_execution_environment(const std::string &command_line);
    void add_DFXML_creator(const std::string &program,const std::string &version,
                           const std::string &svn_r,
                           const std::string &command_line){
        push("creator","version='1.0'");
        xmlout("program",program);
        xmlout("version",version);
        if(svn_r.size()>0) xmlout("svn_version",svn_r);
        add_DFXML_build_environment();
        add_DFXML_execution_environment(command_line);
        pop();                  // creator
    }
    void add_rusage();
    void set_oneline(bool v);
    const std::string &get_outfilename() const {return outfilename; } ;

    /********************************
     *** THESE ARE ALL THREADSAFE ***
     ********************************/
    void comment(const std::string &comment);
    void xmlprintf(const std::string &tag,const std::string &attribute,const char *fmt,...) 
        __attribute__((format(printf, 4, 5))); // "4" because this is "1";
    void xmlout( const std::string &tag,const std::string &value, const std::string &attribute, const bool escape_value);

    /* These all call xmlout or xmlprintf which already has locking, so these are all threadsafe! */
    void xmlout( const std::string &tag,const std::string &value){ xmlout(tag,value,"",true); }
//    void xmlout( const std::string &tag,const int value){ xmlprintf(tag,"","%d",value); }
    void xmloutl(const std::string &tag,const long value){ xmlprintf(tag,"","%ld",value); }
#ifdef WIN32
    void xmlout( const std::string &tag,const int32_t value){ xmlprintf(tag,"","%I32d",value); }
    void xmlout( const std::string &tag,const uint32_t value){ xmlprintf(tag,"","%I32u",value); }
    void xmlout( const std::string &tag,const int64_t value){ xmlprintf(tag,"","%I64d",value); }
    void xmlout( const std::string &tag,const uint64_t value){ xmlprintf(tag,"","%I64u",value); }
#else
    void xmlout( const std::string &tag,const int32_t value){ xmlprintf(tag,"","%" PRId32,value); }
    void xmlout( const std::string &tag,const uint32_t value){ xmlprintf(tag,"","%" PRIu32,value); }
    void xmlout( const std::string &tag,const int64_t value){ xmlprintf(tag,"","%" PRId64,value); }
    void xmlout( const std::string &tag,const uint64_t value){ xmlprintf(tag,"","%" PRIu64,value); }
#ifdef __APPLE__
    void xmlout( const std::string &tag,const size_t value){ xmlprintf(tag,"","%" PRIu64,(unsigned long long)value); }
#endif
#endif
    void xmlout( const std::string &tag,const double value){ xmlprintf(tag,"","%f",value); }
    void xmlout( const std::string &tag,const struct timeval &ts) {
        xmlprintf(tag,"","%d.%06d",(int)ts.tv_sec, (int)ts.tv_usec);
    }
    static std::string to8601(const struct timeval &ts) {
        struct tm tm;
        char buf[64];
#ifdef HAVE_GMTIME_R
        gmtime_r(&ts.tv_sec,&tm);
#else
        time_t t = ts.tv_sec;
        struct tm *tmp;
        tmp = gmtime(&t);
        if(!tmp) return std::string("INVALID");
        tm = *tmp;
#endif
        strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",&tm);
        if(ts.tv_usec>0){
            int len = strlen(buf);
            snprintf(buf+len,sizeof(buf)-len,".%06d",(int)ts.tv_usec);
        }
        strcat(buf,"Z");
        return std::string(buf);
    }
};
#endif

#endif
