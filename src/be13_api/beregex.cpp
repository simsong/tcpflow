#include "config.h"
#include <sys/types.h>
#include <inttypes.h>

#if defined(HAVE_TRE_REGCOMP)
#ifdef HAVE_TRE_TRE_H
#include <tre/tre.h>
#endif
#define REGCOMP tre_regcomp
#define REGFREE tre_regfree
#define REGEXEC tre_regexec
#define nreg (regex_t *)nreg_
#define HAVE_REGEX
static const char *regex_version = "tre";
#endif

#if defined(HAVE_REGCOMP) && !defined(HAVE_REGEX)
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif
#define REGCOMP regcomp
#define REGFREE regfree
#define REGEXEC regexec
#define nreg (regex_t *)nreg_
#define HAVE_REGEX
static const char *regex_version = "system";
#endif

#ifndef HAVE_REGEX
#error bulk_extractor requires tre_regcomp or regcomp to run
#endif

#include "beregex.h"
#include <stdlib.h>
#include <unistd.h>

const char *beregex::version(){return regex_version;}

bool beregex::is_regex(const std::string &str)
{
    for(std::string::const_iterator it = str.begin();it!=str.end();it++){
	switch(*it){
	case '?':
	case '*':
	case '.':
	case '+':
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

void beregex::compile()			// compile the regex
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
int beregex::search(const std::string &line,std::string *found,size_t *offset,size_t *len) const{
    static const int REGMAX=2;
    regmatch_t pmatch[REGMAX];
    if(!nreg_) return 0;
    memset(pmatch,0,sizeof(pmatch));
    int r = REGEXEC(nreg,line.c_str(),REGMAX,pmatch,0);
    if(r==REG_NOMATCH) return 0;
    if(r!=0) return 0;		/* some kind of failure */
    /* Make copies of the first group */
    if(pmatch[1].rm_so != pmatch[1].rm_eo){
	if(found)  *found = line.substr(pmatch[1].rm_so,pmatch[1].rm_eo-pmatch[1].rm_so);
	if(offset) *offset = pmatch[1].rm_so;
	if(len)    *len = pmatch[1].rm_eo-pmatch[1].rm_so;
    }
    return 1;			/* success */
}
/** Perform a search with an array of strings. Return 0 if success, return code if fail.*/
int beregex::search(const std::string &line,std::string *matches,int REGMAX) const {
    regmatch_t *pmatch = (regmatch_t *)calloc(sizeof(regmatch_t),REGMAX+1);
    if(!nreg) return 0;
    int r = REGEXEC(nreg,line.c_str(),REGMAX+1,pmatch,0);
    if(r==0){
	for(int i=0;i<REGMAX;i++){
	    size_t start = pmatch[i+1].rm_so;
	    size_t len   = pmatch[i+1].rm_eo-pmatch[i+1].rm_so;
	    matches[i] = line.substr(start,len);
	}
    }
    free(pmatch);
    return r;
}

int regex_list::readfile(std::string fname)
{
    std::ifstream f(fname.c_str());
    if(f.is_open()){
	while(!f.eof()){
	    std::string line;
	    getline(f,line);
	    if((*line.end())=='\r'){
		line.erase(line.end());	/* remove the last character if it is a \r */
	    }
	    patterns.push_back(new beregex(line,0));
	}
	f.close();
	return 0;
    }
    return -1;
}

bool regex_list::check(const std::string &probe,std::string *found, size_t *offset,size_t *len) const 
{
    /* First check literals, because they are faster */
    if(literal_strings.find(probe)!=literal_strings.end()){
	return true;
    }
    /* Now check the patterns */
    for(std::vector<beregex *>::const_iterator it=patterns.begin(); it != patterns.end(); it++){
	if((*it)->search(probe,found,offset,len)){
	    return true;
	}
    }
    return false;
}
