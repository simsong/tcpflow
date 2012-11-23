/*
 * beregex.h:
 * 
 * simple cover for regular expression class.
 * The class allocates and frees the strings 
 */

#ifndef BEREGEX_H
#define BEREGEX_H

#include "config.h"

#include <string>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <string.h>
#include <vector>
#include <set>

class beregex {
private:
    void compile();
    beregex & operator=(const beregex&that); // don't use this, please
 public:
    /** Bargain-basement detector of things that might be regular expressions. */
    static const char *version();
    static bool is_regex(const std::string &str);

    std::string  pat;		   /* our pattern */
    int     flags;
    void   *nreg_;		// would be regex_t *, but that's in regex.h which is included in beregex.c
    beregex(const beregex &that);
    beregex(std::string pat_,int flags_);
    ~beregex();
    /**
     * perform a search for a single hit. If there is a group and something is found,
     * set *found to be what was found, *offset to be the starting offset, and *len to be
     * the length. Note that this only handles a single group.
     */
    int search(const std::string &line,std::string *found,size_t *offset,size_t *len) const;
    int search(const std::string &line,std::string *matches,int REGMAX) const;
};
typedef std::vector<beregex *> beregex_vector;

/**
 * The regex_list maintains a list of literal strings and regular expressions.
 * The list can be read out of a file.
 * check() returns true if the provided string is inside the list
 * This should be combined with the word_and_context_list
 */
class regex_list {
 public:
    std::set<std::string>literal_strings;			/* static strings */
    std::vector<beregex *> patterns;
    regex_list():literal_strings(),patterns(){}

    size_t size(){
	return literal_strings.size() + patterns.size();
    }
    /**
     * Read a file; returns 0 if successful, -1 if failure.
     * @param fname - the file to read.
     */
    ~regex_list(){
	for(std::vector<beregex *>::iterator it=patterns.begin(); it != patterns.end(); it++){
	    delete *it;
	}
    }
    void add_regex(const std::string &pat){
	patterns.push_back(new beregex(pat,0));
    }
    int readfile(std::string fname);
    /** check() is threadsafe. */
    bool check(const std::string &probe,std::string *found, size_t *offset,size_t *len) const;
};


#endif
