#ifndef CPPMUTEX_H
#define CPPMUTEX_H

#include <stdlib.h>
#include <iostream>
#include <errno.h>
#include <string.h>

/**
 * Cppmutex is an easy-to-use mutex class.
 * Create a cppmutex instance for a mutex.
 * Create a cppmutex::lock(M) object to get a lock; delete the object to free it.
 */
#include <pthread.h>
#include <exception>

class cppmutex {
    class not_impl: public exception {
	const char *what() const throw() {
	    return "copying feature_recorder objects is not implemented.";
	}
    };

    pthread_mutex_t M;
    cppmutex(const cppmutex &c):M(){throw new not_impl();}
    const cppmutex &operator=(const cppmutex &cp){ throw new not_impl();}
public:
    cppmutex():M(){
	if(pthread_mutex_init(&M,NULL)){
	    std::cerr << "pthread_mutex_init failed: " << strerror(errno) << "\n";
	    exit(1);
	}
    }
    virtual ~cppmutex(){
	pthread_mutex_destroy(&M);
    }
    class lock {			// get
    private:
	cppmutex &myMutex;	
	lock(const lock &lock_):myMutex(lock_.myMutex){}
    public:
	lock(cppmutex &m):myMutex(m){
	    pthread_mutex_lock(&myMutex.M);
	}
	~lock(){
	    pthread_mutex_unlock(&myMutex.M);
	}
    };
};

#endif
