/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * beregex.h:
 * 
 * simple cover for regular expression class.
 * The class allocates and frees the strings 
 */

#ifndef BEREGEX_H
#define BEREGEX_H

#ifdef HAVE_TRE_TRE_H
# include <tre/tre.h>
#else
# ifdef HAVE_REGEX_H
#  include <regex.h>
# endif
#endif



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

    std::string  pat;              /* our pattern */
    int     flags;
    // Note: nreg_ is void* because the compiler will not allow us to define it as "struct regex_t *"
    // We could get around this by including regex.h, but that introduces dependencies for programs that include
    // beregex.h.
    void   *nreg_;
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
    std::string search(const std::string &line) const;
};
typedef std::vector<beregex *> beregex_vector;

/**
 * The regex_list maintains a list of regular expressions.
 * The list can be read out of a file.
 * check() returns true if the provided string is inside the list
 * This should be combined with the word_and_context_list
 */
class regex_list {
 public:
    std::vector<beregex *> patterns;
    regex_list():patterns(){}

    size_t size(){
        return patterns.size();
    }
    /**
     * Read a file; returns 0 if successful, -1 if failure.
     * @param fname - the file to read.
     */
    virtual ~regex_list(){
        for(std::vector<beregex *>::iterator it=patterns.begin(); it != patterns.end(); it++){
            delete *it;
        }
    }
    void add_regex(const std::string &pat);
    int readfile(std::string fname);
    /** check() is threadsafe. */
    bool check(const std::string &probe,std::string *found, size_t *offset,size_t *len) const;
};


#endif
