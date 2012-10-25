/*
 * This file is part of tcpflow by Simson Garfinkel <simsong@acm.org>.
 * Originally by Jeremy Elson <jelson@circlemud.org>.
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#define __MAIN_C__

#include "tcpflow.h"
#include <vector>

#define ENABLE_GZIP 0

int debug_level = DEFAULT_DEBUG_LEVEL;
int max_flows = 0;
bool console_output = false;
int suppress_header = 0;
int strip_nonprint = 0;
int use_color = 0;
int max_seek  = 1024*1024*16;
bool opt_no_purge = false;

const char *progname = 0;

extern std::string xml_PRId64;
extern std::string xml_PRIu64;


#ifdef HAVE_PTHREAD
sem_t *semlock = 0;
#endif

#include <string>
#include <semaphore.h>

void print_usage()
{
    std::cerr << PACKAGE << " version " << VERSION << "\n\n";
    std::cerr << "usage: " << progname << " [-achpsv] [-b max_bytes] [-d debug_level] [-f max_fds]\n";
    std::cerr << "          [-i iface] [-L semlock] [-r file] [-R file] [-o outdir] [-X xmlfile]\n";
    std::cerr << "          [-m min_bytes] [-F[ct]] [expression]\n\n";
    std::cerr << "        -a: do ALL processing (http expansion, create report.xml, etc.)\n";
    std::cerr << "        -b: max number of bytes per flow to save\n";
    std::cerr << "        -B: force binary output to console, even with -c or -C\n";
    std::cerr << "        -c: console print only (don't create files)\n";
    std::cerr << "        -C: console print only, but without the display of source/dest header\n";
    std::cerr << "        -d: debug level; default is " << DEFAULT_DEBUG_LEVEL << "\n";
    std::cerr << "        -e: output each flow in alternating colors\n";
    std::cerr << "        -f: maximum number of file descriptors to use\n";
    std::cerr << "        -h: print this help message\n";
    std::cerr << "        -i: network interface on which to listen\n";
    std::cerr << "            (type \"ifconfig -a\" for a list of interfaces)\n";
    std::cerr << "        -L semlock - specifies that writes are locked using a named semaphore\n";
    std::cerr << "        -p: don't use promiscuous mode\n";
    std::cerr << "        -P: don't purge tcp connections on FIN\n";
    std::cerr << "        -r: read packets from tcpdump pcap file (may be repeated)\n";
    std::cerr << "        -R: read packets from tcpdump pcap file TO FINISH CONNECTIONS\n";
    std::cerr << "        -s: strip non-printable characters (change to '.')\n";
    std::cerr << "        -v: verbose operation equivalent to -d 10\n";
    std::cerr << "        -V: print version number and exit\n";
    std::cerr << "        -o outdir   : specify output directory (default '.')\n";
    std::cerr << "        -X filename : DFXML output to filename\n";
    std::cerr << "        -m bytes    : specifies the minimum number of bytes that a stream may\n";
    std::cerr << "                      skip before starting a new stream (default " << max_seek << ").\n";
    std::cerr << "        -AH : extract HTTP objects and unzip GZIP-compressed HTTP messages\n";
    std::cerr << "        -Fc : append the connection counter to ALL filenames\n";
    std::cerr << "        -Ft : prepend the time_t timestamp to ALL filenames\n";
    std::cerr << "        -FT : prepend the ISO8601 timestamp to ALL filenames\n";
    std::cerr << "        -FX : Do not output any files (other than report files)\n";
    std::cerr << "        -FM : Calculate the MD5 for every flow\n";
    std::cerr << "        -T<template> : specify an arbitrary filename template (default " << flow::filename_template << ")\n";
#if ENABLE_GZIP
    std::cerr << "        -Z: do not decompress gzip-compressed HTTP transactions\n";
#endif
    std::cerr << "expression: tcpdump-like filtering expression\n";
    flow::print_usage();
    std::cerr << "\nSee the man page for additional information.\n\n";
}



/**
 * Create the dfxml output
 */

static void dfxml_create(xml &xreport,const std::string &command_line)
{
    xreport.push("dfxml","xmloutputversion='1.0'");
    xreport.push("metadata",
		 "\n  xmlns='http://afflib.org/tcpflow/' "
		 "\n  xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
		 "\n  xmlns:dc='http://purl.org/dc/elements/1.1/'" );
    xreport.xmlout("dc:type","Feature Extraction","",false);
    xreport.pop();
    xreport.add_DFXML_creator(PACKAGE_NAME,PACKAGE_VERSION,"",command_line);
    xreport.push("configuration");
    xreport.pop();			// configuration
}


/* String replace. Perhaps not the most efficient, but it works */
void replace(std::string &str,const std::string &from,const std::string &to)
{
    if(from.size()==0) return;

    std::stringstream ss;
    for(unsigned int i=0;i<str.size();){
	if(str.substr(i,from.size())==from){
	    ss << to;
	    i+=from.size();
	} else {
	    ss << str.at(i);
	    i++;
	}
    }
}

int main(int argc, char *argv[])
{
    bool force_binary_output = false;
    bool opt_all = true;
    char *device = NULL;
    const char *lockname = 0;
    int need_usage = 0;
    std::string reportfilename;
    std::vector<std::string> Rfiles;	// files for finishing
    std::vector<std::string> rfiles;	// files to read
    tcpdemux demux;			// the demux object we will be using.
    std::string command_line = xml::make_command_line(argc,argv);

    /* Make sure that the system was compiled properly */
    bool error = false;
    if(sizeof(struct ip)!=20){
	fprintf(stderr,"COMPILE ERROR. sizeof(struct ip)=%d; should be 20.\n",
		(int)sizeof(struct ip));
	error = true;
    }
    if(sizeof(struct tcphdr)!=20){
	fprintf(stderr,"COMPILE ERROR. sizeof(struct tcphdr)=%d; should be 20.\n",
		(int)sizeof(struct tcphdr));
	error = true;
    }
    if(error){
	fprintf(stderr,"CANNOT CONTINUE\n");
	exit(1);
    }

    progname = argv[0];
    
    init_debug(argv);

    int arg;
    while ((arg = getopt(argc, argv, "aA:Bb:cCd:eF:f:hi:L:m:o:PpR:r:sT:VvX:Z")) != EOF) {
	switch (arg) {
	case 'a':
	    demux.opt_after_header = true;
	    demux.opt_md5 = true;
	    opt_all = true;
	    continue;
	    
	case 'A': 
	    for(const char *cc=optarg;*cc;cc++){
		switch(*cc){
		case 'H': demux.opt_after_header = true;break;
		default:
		    fprintf(stderr,"-A invalid after processing '%c'\n",*cc);
		    need_usage=true;
		}
	    }
	    break;
	case 'b':
	    if ((demux.max_bytes_per_flow = atoi(optarg)) < 0) {
		DEBUG(1) ("warning: invalid value '%s' used with -b ignored", optarg);
		demux.max_bytes_per_flow = 0;
	    } else {
		if(debug_level > 1) {
		    std::cout << "capturing max of " << demux.max_bytes_per_flow << " bytes per flow." << std::endl;
		}
	    }
	    break;
	case 'B':
	    force_binary_output = true; DEBUG(10) ("force binary output");
	    break;
	case 'C':
	    console_output = true;	DEBUG(10) ("printing packets to console only");
	    suppress_header = 1;	DEBUG(10) ("packet header dump suppressed");
	    strip_nonprint = 1;		DEBUG(10) ("converting non-printable characters to '.'");
	    break;
	case 'c':
	    console_output = true;	DEBUG(10) ("printing packets to console only");
	    strip_nonprint = 1;		DEBUG(10) ("converting non-printable characters to '.'");
	    break;
	case 'd':
	    if ((debug_level = atoi(optarg)) < 0) {
		debug_level = DEFAULT_DEBUG_LEVEL;
		DEBUG(1) ("warning: -d flag with 0 debug level '%s'", optarg);
	    }
	    break;
	case 'F':
	    for(const char *cc=optarg;*cc;cc++){
		switch(*cc){
		case 'c': replace(flow::filename_template,"%c","%C"); break;
		case 't': flow::filename_template = "%tT" + flow::filename_template; break;
		case 'T': flow::filename_template = "%T"  + flow::filename_template; break;
		case 'X': demux.opt_output_enabled = false;break;
		case 'M': demux.opt_md5 = true;break;
		default:
		    fprintf(stderr,"-F invalid format specification '%c'\n",*cc);
		    need_usage = true;
		}
	    }
	    break;
	case 'f':
	    if ((demux.max_desired_fds = atoi(optarg)) < (NUM_RESERVED_FDS + 2)) {
		DEBUG(1) ("warning: -f flag must be used with argument >= %d",
			  NUM_RESERVED_FDS + 2);
		demux.max_desired_fds = 0;
	    }
	    break;
	case 'h':
	    print_usage();
	    exit(0);
	    break;
	case 'i': device = optarg; break;
	case 'L': lockname = optarg; break;
	case 'm':
	    max_seek = atoi(optarg);
	    DEBUG(10) ("max_seek set to %d",max_seek); break;
	case 'o': demux.outdir = optarg; break;
	case 'P': opt_no_purge = true; break;
	case 'p': demux.opt_no_promisc = true;
	    DEBUG(10) ("NOT turning on promiscuous mode");
	    break;
	case 'R':
	    Rfiles.push_back(optarg);
	    break;
	case 'r':
	    rfiles.push_back(optarg);
	    break;
	case 's':
	    strip_nonprint = 1;		DEBUG(10) ("converting non-printable characters to '.'"); break;
	case 'T': flow::filename_template = optarg;break;
	case 'V': std::cout << PACKAGE << " " << PACKAGE_VERSION << "\n"; exit (1);
	case 'v': debug_level = 10; break;
	case 'Z': demux.opt_gzip_decompress = 0; break;
	case 'e':
	    use_color  = 1;
	    DEBUG(10) ("using colors");
	    break;
	case 'X': reportfilename = optarg;break;
	default:
	    DEBUG(1) ("error: unrecognized switch '%c'", optopt);
	    need_usage = 1;
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if( (opt_all) && (reportfilename.size()==0) ){
	reportfilename = demux.outdir + "/report.xml";
    }

    /* print help and exit if there was an error in the arguments */
    if (need_usage) {
	print_usage();
	exit(1);
    }

    /* get the user's expression out of remainder of the arg... */
    std::string expression = "";
    for(int i=0;i<argc;i++){
	if(expression.size()>0) expression+=" ";
	expression += argv[i];
    }

    struct stat sbuf;
    if(lockname){
#if defined(HAVE_SEMAPHORE_H) && defined(HAVE_PTHREAD)
	semlock = sem_open(lockname,O_CREAT,0777,1); // get the semaphore
#else
	fprintf(stderr,"%s: attempt to create lock pthreads not present\n",argv[0]);
	exit(1);
#endif	
    }

    if(force_binary_output){
	strip_nonprint = false;
    }

    /* make sure outdir is a directory. If it isn't, try to make it.*/
    if(stat(demux.outdir.c_str(),&sbuf)==0){
	if(!S_ISDIR(sbuf.st_mode)){
	    std::cerr << "outdir is not a directory: " << demux.outdir << "\n";
	    exit(1);
	}
    } else {
	if(MKDIR(demux.outdir.c_str(),0777)){
	    std::cerr << "cannot create " << demux.outdir << ": " << strerror(errno) << "\n";
	    exit(1);
	}
    }

    xml *xreport = 0;
    if(reportfilename.size()>0){
	xreport = new xml(reportfilename,false);
	dfxml_create(*xreport,command_line);
	demux.xreport = xreport;
    }

    argc -= optind;
    argv += optind;

    DEBUG(10) ("%s version %s ", PACKAGE, VERSION);

    if(rfiles.size()==0 && Rfiles.size()==0){
	/* live capture */
#if defined(HAVE_SETUID) && defined(HAVE_GETUID)
	setuid(getuid());	/* Since we don't need network access, drop root privileges */
#endif
        demux.process_infile(expression,device,"",true);
    }

    /* Process rfiles before Rfiles */
    for(std::vector<std::string>::const_iterator it=rfiles.begin();it!=rfiles.end();it++){
	demux.process_infile(expression,device,*it,true);
    }
    for(std::vector<std::string>::const_iterator it=Rfiles.begin();it!=Rfiles.end();it++){
	demux.process_infile(expression,device,*it,false);
    }

    /* -1 causes pcap_loop to loop forever, but it finished when the input file is exhausted. */


    DEBUG(2)("Open FDs at end of processing:      %d",(int)demux.openflows.size());
    DEBUG(2)("Flow map size at end of processing: %d",(int)demux.flow_map.size());

    demux.close_all();
    
    /*
     * Note: funny formats below are a result of mingw problems with PRId64.
     */
    const std::string total_flow_processed("Total flows processed: %"PRId64);
    const std::string total_packets_processed("Total packets processed: %"PRId64);
    
    DEBUG(2)(total_flow_processed.c_str(),demux.flow_counter);
    DEBUG(2)(total_packets_processed.c_str(),demux.packet_counter);

    if(xreport){
	demux.flow_map_clear();	// empty the map to capture the state
	xreport->add_rusage();
	xreport->pop();			// bulk_extractor
	xreport->close();
	delete xreport;		// causes crash on windows with mingw32
    }
    exit(0);			// return(0) causes crash on Windows
}
