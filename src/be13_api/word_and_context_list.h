#ifndef WORD_AND_CONTEXT_LIST_H
#define WORD_AND_CONTEXT_LIST_H

#include "beregex.h"

/**
 * \addtogroup internal_interfaces
 * @{
 * \file
 * word_and_context_list:
 *
 * A re-implementation of the basic stop list, regular expression
 * stop_list, and context-sensitive stop list.
 *
 * Method:
 * Each entry in the stop list can be represented as:
 * - a feature that is stopped, with optional context.
 * - a regular expression
 * 
 * Context is represented as a std::string before the feature and a std::string after.
 * 
 * The stop list contains is a map of features that are stopped. 
 * For each feature, there may be no context or a list of context. 
 * If there is no context and the feature is in the list, 
 */

/*
 * context is a class that records the feature, the text before, and the text after.
 * Typically this is used for stop lists and alert lists. 
 */

#if defined(HAVE_UNORDERED_SET)
#include <unordered_set>
#else
#if defined(HAVE_TR1_UNORDERED_SET)
#include <tr1/unordered_set>
#endif
#endif

/* <unordered_map> includes both unordered_map and unordered_multimap */
#if defined(HAVE_UNORDERED_MAP)
#include <unordered_map>
#else
#if defined(HAVE_TR1_UNORDERED_MAP)
#include <tr1/unordered_map>
#endif
#endif

#include <algorithm>
#include <set>
#include <map>                          // brings in map and multimap

class context {
public:
    static void extract_before_after(const std::string &feature,const std::string &ctx,
                                     std::string &before,std::string &after){
	if(feature.size() <= ctx.size()){
	    /* The most simple algorithm is a sliding window */
	    for(size_t i = 0;i<ctx.size() - feature.size();i++){
		if(ctx.substr(i,feature.size())==feature){
		    before = ctx.substr(0,i);
		    after  = ctx.substr(i+feature.size());
		    return;
		}
	    }
	}
	before.clear();			// can't be done
	after.clear();
    }

    // constructors to make a context with nothing before or after, with just a context, or with all three
    context(const std::string &f):feature(f),before(),after(){}
    context(const std::string &f,const std::string &c):feature(f),before(),after(){
	extract_before_after(f,c,before,after);
    }
    context(const std::string &f,const std::string &b,const std::string &a):feature(f),before(b),after(a){}
    std::string feature;
    std::string before;
    std::string after;
};

inline std::ostream & operator <<(std::ostream &os,const class context &c)
{
    os << "context[" << c.before << "|" << c.feature  << "|" << c.after << "]";
    return os;
}
inline bool operator ==(const class context &a,const class context &b)
{
    return (a.feature==b.feature) && (a.before==b.before) && (a.after==b.after);
}

/**
 * the object that holds the word and context list
 * They aren't atomic, but they are read-only.
 */
class word_and_context_list {
private:
#if defined(HAVE_UNORDERED_MAP)
    typedef std::unordered_multimap<std::string,context> stopmap_t;
#else
#if defined(HAVE_TR1_UNORDERED_MAP)
    typedef std::tr1::unordered_multimap<std::string,context> stopmap_t;
#else
    typedef std::multimap<std::string,context> stopmap_t;
#endif
#endif
    stopmap_t fcmap;			// maps features to contexts; for finding them

#if defined(HAVE_UNORDERED_SET)
    typedef std::unordered_set< std::string > stopset_t;
#else
#if defined(HAVE_TR1_UNORDERED_SET)
    typedef std::tr1::unordered_set< std::string > stopset_t;
#else
    typedef std::set< std::string > stopset_t;
#endif
#endif
    stopset_t context_set;			// presence of a pair in fcmap

    beregex_vector patterns;
public:
    /**
     * rstrcmp is like strcmp, except it compares std::strings right-aligned
     * and only compares the minimum sized std::string of the two.
     */
    static int rstrcmp(const std::string &a,const std::string &b);

    word_and_context_list():fcmap(),context_set(),patterns(){ }
    ~word_and_context_list(){
	for(beregex_vector::iterator it=patterns.begin(); it != patterns.end(); it++){
	    delete *it;
	}
    }
    size_t size(){ return fcmap.size() + patterns.size();}
    void add_regex(const std::string &pat);	// not threadsafe
    bool add_fc(const std::string &f,const std::string &c); // not threadsafe
    int readfile(const std::string &fname);	// not threadsafe

    // return true if the probe with context is in the list or in the stopmap
    bool check(const std::string &probe,const std::string &before, const std::string &after) const; // threadsafe
    bool check_feature_context(const std::string &probe,const std::string &context) const; // threadsafe
    void dump();
};


inline int word_and_context_list::rstrcmp(const std::string &a,const std::string &b)
{
    size_t alen = a.size();
    size_t blen = b.size();
    size_t len = alen < blen ? alen : blen;
    for(size_t i=0;i<len;i++){
	size_t apos = alen - len + i;
	size_t bpos = blen - len + i;
	if(a[apos] < b[bpos]) return -1;
	if(a[apos] > b[bpos]) return 1;
    }
    return 0;
}

#endif
