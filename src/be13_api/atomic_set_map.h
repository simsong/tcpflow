/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/**
 * defines atomic_map and atomic_set
 *
 */

#ifndef ATOMIC_SET_MAP_H
#define ATOMIC_SET_MAP_H


#include "cppmutex.h"
#include <algorithm>
#include <set>
#include <map>

#if defined(HAVE_UNORDERED_MAP)
# include <unordered_map>
# undef HAVE_TR1_UNORDERED_MAP           // be sure we don't use it
#else
# if defined(HAVE_TR1_UNORDERED_MAP)
#  include <tr1/unordered_map>
# endif
#endif

#if defined(HAVE_UNORDERED_SET)
#include <unordered_set>
#undef HAVE_TR1_UNORDERED_SET           // be sure we don't use it
#else
#if defined(HAVE_TR1_UNORDERED_SET)
#include <tr1/unordered_set>
#endif
#endif

template <class TYPE,class CTYPE> class atomic_histogram {
#ifdef HAVE_UNORDERED_MAP
    typedef std::unordered_map<TYPE,CTYPE> hmap_t;
#else
#ifdef HAVE_TR1_UNORDERED_MAP
    typedef std::tr1::unordered_map<TYPE,CTYPE> hmap_t;
#else
    typedef std::map<TYPE,CTYPE> hmap_t;
#endif
#endif
    hmap_t amap; // the locked atomic map
    mutable cppmutex M;                         // my lock
public:
    atomic_histogram():amap(),M(){};

    // The callback is used to report the histogram.
    // The callback returns '0' if no error is encountered, '-1' if the dumping should stop
    typedef int (*dump_callback_t)(void *user,const TYPE &val,const CTYPE &count);
    // add and return the count
    // http://www.cplusplus.com/reference/unordered_map/unordered_map/insert/
    CTYPE add(const TYPE &val,const CTYPE &count){
        cppmutex::lock lock(M);
        std::pair<typename hmap_t::iterator,bool> p = amap.insert(std::make_pair(val,count));

        if (!p.second) {
            p.first->second += count;
        }
        return p.first->second;
    }

    // Dump the database to a user-provided callback.
    void     dump(void *user,dump_callback_t dump_cb) const{
        cppmutex::lock lock(M);
        for(typename hmap_t::const_iterator it = amap.begin();it!=amap.end();it++){
            int ret = (*dump_cb)(user,(*it).first,(*it).second);
            if(ret<0) return;
        }
    }
    struct ReportElement {
        ReportElement(TYPE aValue,uint64_t aTally):value(aValue),tally(aTally){ }
        TYPE value;
        CTYPE tally;
        static bool compare(const ReportElement *e1,
                            const ReportElement *e2) {
	    if (e1->tally > e2->tally) return true;
	    if (e1->tally < e2->tally) return false;
	    return e1->value < e2->value;
	}
        virtual ~ReportElement(){};
    };
    typedef std::vector< const ReportElement *> element_vector_t;

    void     dump_sorted(void *user,dump_callback_t dump_cb) const {
        /* Create a list of new elements, sort it, then report the sorted list */
        element_vector_t  evect;
        {
            cppmutex::lock lock(M);
            for(typename hmap_t::const_iterator it = amap.begin();it!=amap.end();it++){
                evect.push_back( new ReportElement((*it).first, (*it).second));
            }
        }
        std::sort(evect.begin(),evect.end(),ReportElement::compare);
        for(typename element_vector_t::const_iterator it = evect.begin();it!=evect.end();it++){
            int ret = (*dump_cb)(user,(*it)->value,(*it)->tally);
            delete *it;
            if(ret<0) break;
        }

    }
    uint64_t size_estimate() const;     // Estimate the size of the database 
};

template <class TYPE > class atomic_set {
    cppmutex M;
#ifdef HAVE_UNORDERED_SET
    std::unordered_set<TYPE>myset;
#else
#ifdef HAVE_TR1_UNORDERED_SET
    std::tr1::unordered_set<TYPE>myset;
#else
    std::set<TYPE>myset;
#endif
#endif
public:
    atomic_set():M(),myset(){}
    bool contains(const TYPE &s){
        cppmutex::lock lock(M);
        return myset.find(s)!=myset.end();
    }
    void insert(const TYPE &s){
        cppmutex::lock lock(M);
        myset.insert(s);
    }
    bool check_for_presence_and_insert(const TYPE &s){
        cppmutex::lock lock(M);
        if(myset.find(s)!=myset.end()) return true; // in the set
        myset.insert(s);                // otherwise insert it
        return false;                   // and return that it wasn't
    }
};

#endif
