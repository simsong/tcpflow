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
extern int max_desired_fds;

#define BUFSIZE 1024


/****************************************************************/
/* C++ string splitting code from http://stackoverflow.com/questions/236129/how-to-split-a-string-in-c */
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while(std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    return split(s, delim, elems);
}

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
    return string(buf);
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


/*
 * Remember our program name and process ID so we can use them later
 * for printing debug messages
 */
void init_debug(char *argv[])
{
    debug_prefix = (char *)calloc(sizeof(char), strlen(argv[0]) + 16);
    if(debug_prefix==0) die("malloc failed");
    sprintf(debug_prefix, "%s[%d]", argv[0], (int) getpid());
}


void mkdirs_for_path(std::string path)
{
    static std::set<std::string> made_dirs;
    if(path.size()==0);

    std::string mpath;

    if(path.at(0)=='/'){
        std::cerr << "path begins / " << path << "\n" ;
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
                int r = mkdir(mpath.c_str(),0777);
                if(r<0 && errno!=EEXIST){
                    perror(mpath.c_str());
                    exit(1);
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

