/*
 * This file is part of tcpflow.
 * Originally by Jeremy Elson <jelson@circlemud.org>
 * Now maintained by Simson L. Garfinkel <simsong@acm.org>
 *
 * This source code is under the GNU Public License (GPL).  
 * See LICENSE for details.
 *
 */

#include "tcpflow.h"

#include <iomanip>

static char *debug_prefix = NULL;

/*
 * STD String sprintf wrapper for sane CPP formatting
 */
std::string ssprintf(const char *fmt,...)
{
    char buf[65536];
    va_list ap;
    va_start(ap,fmt);
    vsnprintf(buf,sizeof(buf),fmt,ap);
    va_end(ap);
    return std::string(buf);
}

/*
 * Insert readability commas into an integer without writing a custom locale facet
 */
std::string comma_number_string(int64_t input)
{
    std::vector<int16_t> tokens;
    std::stringstream ss;
    ss << std::setfill('0');
    int sign = 1;

    if(input < 0) {
        sign = -1;
        input *= -1;
    }

    while(input >= 1000) {
        tokens.push_back(input % 1000);
        input /= 1000;
    }

    ss << (input * sign);

    for(std::vector<int16_t>::const_reverse_iterator it = tokens.rbegin();
            it != tokens.rend(); it++) {
        ss << "," << std::setw(3) << *it;
    }

    return ss.str();
}


std::string macaddr(const uint8_t *addr)
{
    char buf[256];
    snprintf(buf,sizeof(buf),"%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
    return std::string(buf);
}

/*
 * Remember our program name and process ID so we can use them later
 * for printing debug messages
 *
 */
void init_debug(const char *pfx,int include_pid)
{
    if(debug_prefix) free(debug_prefix);
    size_t debug_prefix_size = strlen(pfx) + 16;
    debug_prefix = (char *)calloc(sizeof(char), debug_prefix_size);
    if(debug_prefix==0) die("malloc failed");
    if(include_pid){
        snprintf(debug_prefix, debug_prefix_size, "%s[%d]", pfx, (int) getpid());
    } else {
        snprintf(debug_prefix, debug_prefix_size, "%s", pfx);
    }
}


/****************************************************************/
/* C++ string splitting code from http://stackoverflow.com/questions/236129/how-to-split-a-string-in-c */
#if 0
static std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems)
{
    std::stringstream ss(s);
    std::string item;
    while(std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

static std::vector<std::string> split(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    return split(s, delim, elems);
}
#endif


/* mkdir all of the containing directories in path.
 * keep track of those made so we don't need to keep remaking them.
 */
void mkdirs_for_path(std::string path)
{
    static std::set<std::string> made_dirs; // track what we made

    std::string mpath;                  // the path we are making

    if(path.at(0)=='/'){
        mpath = "/";
        path = path.substr(1);
    }

    std::vector<std::string> parts = split(path,'/');

    /* Notice that this won't mkdir for the last part.
     * That's okay, because it's a filename.
     */
    for(std::vector<std::string>::const_iterator it=parts.begin();it!=parts.end();it++){
        if(made_dirs.find(mpath)==made_dirs.end()){
            if(mpath.size()){
                int r = MKDIR(mpath.c_str(),0777);
                if(r<0){
                    /* Can't make path; see if we can execute it*/
                    if(access(mpath.c_str(),X_OK)<0){
                        perror(mpath.c_str());
                        exit(1);
                    }
                }
                made_dirs.insert(mpath);
            }
        }
        if(mpath.size()>0) mpath += "/";
        mpath += *it;
    }
}

/*
 * Print a debugging message, given a va_list
 */
void print_debug_message(const char *fmt, va_list ap)
{
    /* print debug prefix */
    fprintf(stderr, "%s: ", debug_prefix);

    /* print the var-arg buffer passed to us */
    vfprintf(stderr, fmt, ap);

    /* add newline */
    fprintf(stderr, "\n");
    (void) fflush(stderr);
}

/* Print a debugging or informational message */
void debug_real(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_debug_message(fmt, ap);
    va_end(ap);
}
  

/* Print a debugging or informatioal message, then exit  */
void die(const char *fmt, ...) 
{
    va_list ap;

    va_start(ap, fmt);
    print_debug_message(fmt, ap);
    exit(1);
}

/* An attempt at making signal() portable.
 *
 * If we detect sigaction, use that; 
 * otherwise if we have setsig, use that;
 * otherwise, cross our fingers and hope for the best using plain old signal().
 *
 * Our first choice is sigaction (sigaction() is POSIX; signal() is
 * not.)  Taken from Stevens' _Advanced Programming in the UNIX Environment_.
 *
 * 10/6/08 - slg - removed RETSIGTYPE, since it hasn't been needed to 15 years
 */
void (*portable_signal(int signo, void (*func)(int)))(int)
{
#if defined(HAVE_SIGACTION)
    struct sigaction act, oact;

    memset(&act, 0, sizeof(act));
    memset(&oact, 0, sizeof(oact));
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(signo, &act, &oact) < 0) return (SIG_ERR);
    return (oact.sa_handler);
#elif defined(HAVE_SIGSET)
    return sigset(signo, func);
#else
    return signal(signo, func);
#endif /* HAVE_SIGACTION, HAVE_SIGSET */
}


/************
 *** MMAP ***
 ************/

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

/**
 * fake implementation of mmap and munmap if we don't have them
 */
#if !defined(HAVE_MMAP)
#define PROT_READ 0
#define MAP_FILE 0
#define MAP_SHARED 0
void *mmap(void *addr,size_t length,int prot, int flags, int fd, off_t offset)
{
    void *buf = (void *)malloc(length);
    if(!buf) return 0;
    read(fd,buf,length);			// should explore return code
    return buf;
}

void munmap(void *buf,size_t size)
{
    free(buf);
}

#endif

