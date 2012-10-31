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


class cppmutex {
    pthread_mutex_t M;
public:
    cppmutex():M(){
	if(pthread_mutex_init(&M,NULL)){
	    std::cerr << "pthread_mutex_init failed: " << strerror(errno) << "\n";
	    exit(1);
	}
    }
    ~cppmutex(){
	pthread_mutex_destroy(&M);
    }
    class lock {			// get
    private:
	cppmutex &myMutex;
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
