/*
 * Simson's XML output class.
 * Include this AFTER your config file with the HAVE statements.
 * Optimized for DFXML generation.
 */

#ifndef _XML_H_
#define _XML_H_

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
#include <sstream>
#include <string>
#include <stack>
#include <map>
#include <set>

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
class xml {
private:
    /*** neither copying nor assignment is implemented ***
     *** We do this by making them private constructors that throw exceptions. ***/
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying feature_recorder objects is not implemented.";
	}
    };
    xml(const xml &fr):
	M(),outf(),out(),tags(),tag_stack(),tempfilename(),tempfile_template(),t0(),
	make_dtd(),outfilename(),oneline(){
	throw new not_impl();
    }
    const xml &operator=(const xml &x){ throw new not_impl(); }
    /****************************************************************/

    typedef std::set<std::string> stringset;

    cppmutex  M;			// mutext protecting out
    std::fstream outf;
    std::ostream *out;			// where it is being written; defaulst to stdout
    stringset tags;			// XML tags
    std::stack<std::string>tag_stack;
    std::string  tempfilename;
    std::string  tempfile_template;
    struct timeval t0;
    bool  make_dtd;
    std::string outfilename;
    void  write_doctype(std::fstream &out);
    void  verify_tag(std::string tag);
    void  spaces();			// print spaces corresponding to tag stack
    static std::string xml_PRId64;	// for compiler bug
    bool oneline;
public:
    static std::string make_command_line(int argc,char * const *argv){
	std::string command_line;
	for(int i=0;i<argc;i++){
	    if(i>0) command_line.push_back(' ');
	    command_line.append(argv[i]);
	}
	return command_line;
    }

    typedef std::map<std::string,std::string> tagmap_t;
    typedef std::set<std::string> tagid_set_t;

    class existing {
    public:;
	tagmap_t    *tagmap;
	std::string *tagid;
	const std::string *attrib;
	stringset *tagid_set;
    };

    xml();					 // defaults to stdout
    xml(const std::string &outfilename,bool makeDTD); // write to a file, optionally making a DTD
    xml(const std::string &outfilename,class existing &e); // open an existing file, for appending
    virtual ~xml(){};
    void set_tempfile_template(const std::string &temp);

    static std::string xmlescape(const std::string &xml);
    static std::string xmlstrip(const std::string &xml);

    /** xmlmap turns a map into an XML block */
    typedef std::map<std::string,std::string> strstrmap_t;
    static std::string xmlmap(const strstrmap_t &m,const std::string &outer,const std::string &attrs);

    /**
     * opens an existing XML file and jumps to the end.
     * @param tagmap  - any keys that are tags capture the values.
     * @param tagid   - if a tagid is provided, fill tagid_set with all of the tags seen.
     */
    void open_existing(tagmap_t *tagmap,std::string *tagid,const std::string *attrib,tagid_set_t *tagid_set);
    void close();			// writes the output to the file

    void flush(){outf.flush();}
    void tagout( const std::string &tag,const std::string &attribute);
    void push(const std::string &tag,const std::string &attribute);
    void push(const std::string &tag) {push(tag,"");}

    // writes a std::string as parsed data
    void puts(const std::string &pdata);

    // writes a std::string as parsed data
    void printf(const char *fmt,...) __attribute__((format(printf, 2, 3))); // "2" because this is "1"
    void pop();	// close the tag

    void add_DFXML_build_environment();
    static void cpuid(uint32_t op, unsigned long *eax, unsigned long *ebx,
	       unsigned long *ecx, unsigned long *edx);
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
	pop();			// creator
    }
    void add_rusage();
    void set_oneline(bool v);

    /******************************************
     *** THESE ARE ALL THREADSAFE ROUTINES! ***
     ******************************************/
    void comment(const std::string &comment);
    void xmlprintf(const std::string &tag,const std::string &attribute,const char *fmt,...) 
	__attribute__((format(printf, 4, 5))); // "4" because this is "1";
    void xmlout( const std::string &tag,const std::string &value, const std::string &attribute,
		 const bool escape_value);

    /* These all call xmlout or xmlprintf which already has locking, so these are all threadsafe! */
    void xmlout( const std::string &tag,const std::string &value){ xmlout(tag,value,"",true); }
    void xmlout( const std::string &tag,const int value){ xmlprintf(tag,"","%d",value); }
    void xmloutl(const std::string &tag,const long value){ xmlprintf(tag,"","%ld",value); }
    void xmlout( const std::string &tag,const int64_t value){ xmlprintf(tag,"",xml_PRId64.c_str(),value); }
    void xmlout( const std::string &tag,const double value){ xmlprintf(tag,"","%f",value); }
    void xmlout( const std::string &tag,const struct timeval &ts) {
	char buf[64];
	snprintf(buf,sizeof(buf),"%d.%06d",(int)ts.tv_sec, (int)ts.tv_usec);
	xmlout(tag,buf);
    }
};
#endif

#endif
