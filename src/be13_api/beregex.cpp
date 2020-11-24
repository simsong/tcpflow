/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "config.h"
#include "beregex.h"

#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>


#if defined(HAVE_LIBTRE) && defined(HAVE_TRE_REGCOMP) && defined(HAVE_TRE_TRE_H)
#define REGCOMP tre_regcomp
#define REGFREE tre_regfree
#define REGEXEC tre_regexec
#define nreg (regex_t *)nreg_
#define HAVE_REGULAR_EXPRESSIONS
static const char *regex_version = "tre";
#endif

/* use regcomp() if tre_regcomp() is not available */
#if defined(HAVE_REGCOMP) && !defined(HAVE_REGULAR_EXPRESSIONS)
#define REGCOMP regcomp
#define REGFREE regfree
#define REGEXEC regexec
#define nreg (regex_t *)nreg_
#define HAVE_REGULAR_EXPRESSIONS
static const char *regex_version = "system";
#endif

#ifndef HAVE_REGULAR_EXPRESSIONS
#error bulk_extractor requires tre_regcomp or regcomp to run
#error download tre from "http://laurikari.net/tre/download/"
#endif

const char *beregex::version(){return regex_version;}

/* Only certain characters are assumed to be a regular expression. These characters are
 * coincidently never in email addresses.
 */
bool beregex::is_regex(const std::string &str)
{
    for(std::string::const_iterator it = str.begin();it!=str.end();it++){
        switch(*it){
        case '*':
        case '[':
        case '(':
            return true;
        }
    }
    return false;
}

beregex::beregex(const beregex &that):pat(that.pat),flags(that.flags),nreg_(0)
{
    compile();
}

beregex::beregex(std::string pat_,int flags_):pat(pat_),flags(flags_),nreg_(0)
{
    compile();
}

void beregex::compile()                 // compile the regex
{
    if(pat.size()==0) return;
    nreg_ = calloc(sizeof(regex_t),1);
    if(REGCOMP(nreg,pat.c_str(),flags | REG_EXTENDED)!=0){
        std::cerr << "regular expression compile error '" << pat << "' flags=" << flags << "\n";
        exit(1);
    }
}
beregex::~beregex(){
    if(nreg_){
        REGFREE(nreg);
        free(nreg_);
        nreg_ = 0;
    }
}
/**
 * perform a search for a single hit. If there is a group and something is found,
 * set *found to be what was found, *offset to be the starting offset, and *len to be
 * the length. Note that this only handles a single group.
 */
int beregex::search(const std::string &line,std::string *found,size_t *offset,size_t *len) const
{
    static const int REGMAX=2;
    regmatch_t pmatch[REGMAX];
    if(!nreg_) return 0;
    memset(pmatch,0,sizeof(pmatch));
    int r = REGEXEC(nreg,line.c_str(),REGMAX,pmatch,0);
    if(r==REG_NOMATCH) return 0;
    if(r!=0) return 0;                  /* some kind of failure */
                                        /* Make copies of the first group */
    if(pmatch[1].rm_so != pmatch[1].rm_eo){
        if(found)  *found  = line.substr(pmatch[1].rm_so,pmatch[1].rm_eo-pmatch[1].rm_so);
        if(offset) *offset = pmatch[1].rm_so;
        if(len)    *len    = pmatch[1].rm_eo-pmatch[1].rm_so;
    }
    return 1;                           /* success */
}
/** Perform a search with an array of strings. Return 0 if success, return code if fail.*/

int beregex::search(const std::string &line,std::string *matches,int REGMAX) const {
    if(!nreg) return 0;
    regmatch_t *pmatch = (regmatch_t *)calloc(sizeof(regmatch_t),REGMAX+1);
    int r = REGEXEC(nreg,line.c_str(),REGMAX+1,pmatch,0);
    if(r==0){
        for(int i=0;i<REGMAX;i++){
            size_t start = pmatch[i+1].rm_so;
            size_t len   = pmatch[i+1].rm_eo-pmatch[i+1].rm_so;
            matches[i]   = line.substr(start,len);
        }
    }
    free(pmatch);
    return r;
}

std::string beregex::search(const std::string &line) const
{
    if(!nreg) return std::string();
    regmatch_t pmatch[2];
    memset(pmatch,0,sizeof(pmatch));
    if(REGEXEC(nreg,line.c_str(),2,pmatch,0)==0){
        size_t start = pmatch[1].rm_so;
        size_t len   = pmatch[1].rm_eo-pmatch[1].rm_so;
        return line.substr(start,len);
    }
    else {
        return std::string();
    }
}

int regex_list::readfile(std::string fname)
{
    std::ifstream f(fname.c_str());
    if(f.is_open()){
        while(!f.eof()){
            std::string line;
            getline(f,line);
            if(line.size()>0 && (*line.end())=='\r'){
                line.erase(line.end()); /* remove the last character while it is a \n or \r */
            }
            patterns.push_back(new beregex(line,0));
        }
        f.close();
        return 0;
    }
    return -1;
}

void regex_list::add_regex(const std::string &pat)
{
    patterns.push_back(new beregex(pat,0));
}


/* Find the FIRST match in buf */
bool regex_list::check(const std::string &buf,std::string *found, size_t *offset,size_t *len) const 
{
    /* Now check check pattern */
    /* First check literals, because they are faster */
    bool first = true;
    bool fnd = false;
    for(std::vector<beregex *>::const_iterator it=patterns.begin(); it != patterns.end(); it++){
        std::string nfound;
        size_t      noffset=0;
        size_t      nlen=0;
        if((*it)->search(buf,&nfound,&noffset,&nlen)){
            if(first || noffset<*offset){
                fnd     = true;
                *found  = nfound;
                *offset = noffset;
                *len    = nlen;
                first   = false;
            }
        }
    }
    return fnd;
}

