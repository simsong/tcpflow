/*
 * This file is part of tcpflow by Simson Garfinkel <simsong@acm.org>.
 * Originally by Jeremy Elson <jelson@circlemud.org>.
 *
 * This source code is under the GNU Public License (GPL) version 3.
 * See COPYING for details.
 *
 */

#define __MAIN_C__

#include "config.h"

#include "tcpflow.h"

#include "tcpip.h"
#include "tcpdemux.h"
#include "bulk_extractor_i.h"
#include "iptree.h"

#include "be13_api/utils.h"

#include <string>
#include <vector>
#include <sys/types.h>
#include <dirent.h>
#include <getopt.h>      // getopt_long()

#ifdef HAVE_GRP_H
#  include <grp.h>       // initgroups()
#endif

/* bring in inet_ntop if it is not present */
#define ETH_ALEN 6
#ifndef HAVE_INET_NTOP
#include "inet_ntop.c"
#endif

#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif

/* droproot is from tcpdump.
 * See https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.c#L611
 */
const char *program_name = 0;
const char *tcpflow_droproot_username = 0;
const char *tcpflow_chroot_dir = 0;

int packet_buffer_timeout = 10;

scanner_info::scanner_config be_config; // system configuration

typedef struct {
    const char *name;
    const char *dvalue;
    const char *help;
} default_t;

default_t defaults[] = {
    {"tdelta","0","Time delta in seconds"},
    {"packet-buffer-timeout", "10", "Time in milliseconds between each callback from libpcap"},
    {0,0,0}
};

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

const char *progname = 0;		// name of the program
int debug = DEFAULT_DEBUG_LEVEL;	// global variable, not clear why

/* semaphore prevents multiple copies from outputing on top of each other */
#ifdef HAVE_PTHREAD_H
#include <semaphore.h>
sem_t *semlock = 0;
#endif

#define DEFAULT_REPORT_FILENAME "report.xml"

/****************************************************************
 *** SCANNER PLUG-IN SYSTEM
 ****************************************************************/

scanner_t *scanners_builtin[] = {
    scan_md5,
    scan_http,
    scan_netviz,
// removed scan_python becasue it does not support Python 3
//    scan_python,
    scan_tcpdemux,
#ifdef USE_WIFI
    scan_wifiviz,
#endif
    0};

bool opt_no_promisc = false;		// true if we should not use promiscious mode

/* Long options!
 *
 * We need more long options; developers looking at this file should
 * feel free to submit more!
 */

static const struct option longopts[] = {
    { "chroot", required_argument, NULL, 'z' },
    { "help", no_argument, NULL, 'h' },
    { "relinquish-privileges", required_argument, NULL, 'U' },
    { "verbose", no_argument, NULL, 'v' },
    { "version", no_argument, NULL, 'V' },
    { NULL, 0, NULL, 0 }
};


/****************************************************************
 *** USAGE
 ****************************************************************/

static void usage(int level)
{
    std::cout << PACKAGE_NAME << " version " << PACKAGE_VERSION << "\n\n";
    std::cout << "usage: " << progname << " [-aBcCDhIpsvVZ] [-b max_bytes] [-d debug_level] \n";
    std::cout << "     [-[eE] scanner] [-f max_fds] [-F[ctTXMkmg]] [-h|--help] [-i iface]\n";
    std::cout << "     [-l files...] [-L semlock] [-m min_bytes] [-o outdir] [-r file] [-R file]\n";
    std::cout << "     [-S name=value] [-T template] [-U|--relinquish-privileges user] [-v|--verbose]\n";
    std::cout << "     [-w file] [-x scanner] [-X xmlfile] [-z|--chroot dir] [expression]\n\n";
    std::cout << "   -a: do ALL post-processing.\n";
    std::cout << "   -b max_bytes: max number of bytes per flow to save\n";
    std::cout << "   -d debug_level: debug level; default is " << DEFAULT_DEBUG_LEVEL << "\n";
    std::cout << "   -f: maximum number of file descriptors to use\n";
    std::cout << "   -h: print this help message (-hh for more help)\n";
    std::cout << "   -H: print detailed information about each scanner\n";
    std::cout << "   -i: network interface on which to listen\n";
    std::cout << "   -I: write for each flow another file *.findx to provide byte-indexed timestamps\n";
    std::cout << "   -g: output each flow in alternating colors (note change!)\n";
    std::cout << "   -l: treat non-flag arguments as input files rather than a pcap expression\n";
    std::cout << "   -L  semlock - specifies that writes are locked using a named semaphore\n";
    std::cout << "   -p: don't use promiscuous mode\n";
    std::cout << "   -q: quiet mode - do not print warnings\n";

    std::cout << "   -r file      : read packets from tcpdump pcap file (may be repeated)\n";
    std::cout << "   -R file      : read packets from tcpdump pcap file TO FINISH CONNECTIONS\n";
    std::cout << "   -v           : verbose operation equivalent to -d 10\n";
    std::cout << "   -V           : print version number and exit\n";
    std::cout << "   -w  file     : write packets not processed to file\n";
    std::cout << "   -o  outdir   : specify output directory (default '.')\n";
    std::cout << "   -X  filename : DFXML output to filename\n";
    std::cout << "   -m  bytes    : specifies skip that starts a new stream (default "
              << (unsigned)tcpdemux::options::MAX_SEEK << ").\n";
    std::cout << "   -F{p} : filename prefix/suffix (-hh for options)\n";
    std::cout << "   -T{t} : filename template (-hh for options; default "
              << flow::filename_template << ")\n";
    std::cout << "   -Z       do not decompress gzip-compressed HTTP transactions\n";
    std::cout << "   -K: output|keep pcap flow structure.\n";

    std::cout << "\nSecurity:\n";
    std::cout << "   -U user  relinquish privleges and become user (if running as root)\n";
    std::cout << "   -z dir   chroot to dir (requires that -U be used).\n";

    std::cout << "\nControl of Scanners:\n";
    std::cout << "   -E scanner   - turn off all scanners except scanner\n";
    std::cout << "   -S name=value  Set a configuration parameter (-hh for info)\n";
    if(level > 1) {
        std::cout << "\n" "Activated options -S name=value:";
        for(int i=0;defaults[i].name;i++){
            std::cout <<"\n   -S "<< defaults[i].name << "=" << defaults[i].dvalue <<'\t'<< defaults[i].help;
        }
        std::cout << '\n';
        be13::plugin::info_scanners(false,true,scanners_builtin,'e','x');
    }
    std::cout << "\n"
                 "Console output options:\n";
    std::cout << "   -B: binary output, even with -c or -C (normally -c or -C turn it off)\n";
    std::cout << "   -c: console print only (don't create files)\n";
    std::cout << "   -C: console print only, but without the display of source/dest header\n";
    std::cout << "   -0: don't print newlines after packets when printing to console\n";
    std::cout << "   -s: strip non-printable characters (change to '.')\n";
    std::cout << "   -J: output json format.\n";
    std::cout << "   -D: output in hex (useful to combine with -c or -C)\n";
    std::cout << "\n";
#ifndef HAVE_LIBCAIRO
    std::cout << "Rendering not available because Cairo was not installed.\n\n";
#endif
    std::cout << "expression: tcpdump-like filtering expression\n";
    std::cout << "\nSee the man page for additional information.\n\n";
    if(level<2) return;
    std::cout << "Filename Prefixes:\n";
    std::cout << "   -Fc : append the connection counter to ALL filenames\n";
    std::cout << "   -Ft : prepend the time_t UTC timestamp to ALL filenames\n";
    std::cout << "   -FT : prepend the ISO8601 UTC timestamp to ALL filenames\n";
    std::cout << "   -FX : Do not output any files (other than report files)\n";
    std::cout << "   -FM : Calculate the MD5 for every flow (stores in DFXML)\n";
    std::cout << "   -Fk : Bin output in 1K directories\n";
    std::cout << "   -Fm : Bin output in 1M directories (2 levels)\n";
    std::cout << "   -Fg : Bin output in 1G directories (3 levels)\n";
    flow::usage();
    std::cout << "\n" "Current limitations:"
                 "\n" "  get_max_fds() = " << tcpdemux::getInstance()->get_max_fds();
    std::cout << "\n" "  NUM_RESERVED_FDS = " << NUM_RESERVED_FDS;
    std::cout << '\n';
}

/**
 * Create the dfxml output
 */

static void dfxml_create(class dfxml_writer &xreport,const std::string &command_line)
{
    xreport.push("dfxml","xmloutputversion='1.0'");
    xreport.push("metadata",
		 "\n  xmlns='http://afflib.org/tcpflow/' "
		 "\n  xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
		 "\n  xmlns:dc='http://purl.org/dc/elements/1.1/'" );
    xreport.xmlout("dc:type","Feature Extraction","",false);
    xreport.pop();
    xreport.add_DFXML_creator(PACKAGE_NAME,PACKAGE_VERSION,"",command_line);
}


/* String replace. Perhaps not the most efficient, but it works */
void replace(std::string &str,const std::string &from,const std::string &to)
{
    if(from.size()==0) return;
    bool changed = false;

    std::stringstream ss;
    for(unsigned int i=0;i<str.size();){
	if(str.substr(i,from.size())==from){
	    ss << to;
	    i+=from.size();
	    changed = true;
	} else {
	    ss << str.at(i);
	    i++;
	}
    }
    if(changed) str = ss.str();			// copy over original
}

/* These must be global variables so they are available in the signal handler */
feature_recorder_set *the_fs = 0;
dfxml_writer *xreport = 0;
pcap_t *pd = 0;
void terminate(int sig)
{
    if (sig == SIGHUP || sig == SIGINT || sig == SIGTERM) {
        DEBUG(1) ("terminating orderly");
        pcap_breakloop(pd);
        return;
    } else {
        DEBUG(1) ("terminating");
        be13::plugin::phase_shutdown(*the_fs);	// give plugins a chance to do a clean shutdown
        exit(0); /* libpcap uses onexit to clean up */
    }
}

#ifdef HAVE_FORK
#include <sys/wait.h>
// transparent decompression for process_infile
class inflater {
    const std::string suffix;
    const std::string invoc_format;
public:
    inflater(const std::string &suffix_, const std::string &invoc_format_) :
        suffix(suffix_), invoc_format(invoc_format_) {}
    // is this inflater appropriate for a given file?
    bool appropriate(const std::string &file_path) const
    {
        return ends_with(file_path,suffix);
    }
    // invoke the inflater in a shell, and return the file descriptor to read the inflated file from
    int invoke(const std::string &file_path, int* ppid) const
    {
        std::string invocation = ssprintf(invoc_format.c_str(), file_path.c_str());
        int pipe_fds[2];
        if(!system(NULL)) {
            std::cerr << "no shell available to decompress '" << file_path << "'" << std::endl;
            return -1;
        }
        if(pipe(pipe_fds)) {
            std::cerr << "failed to create pipe to decompress '" << file_path << "'" << std::endl;
            return -1;
        }

        pid_t child_pid;
        child_pid = fork();
        if(child_pid == -1) {
            std::cerr << "failed to fork child to decompress '" << file_path << "'" << std::endl;
            return -1;
        }
        if(child_pid == 0) {
            // decompressor
            close(pipe_fds[0]);
            dup2(pipe_fds[1], 1);
            if(system(invocation.c_str())) {
                std::cerr << "decompressor reported error inflating '" << file_path << "'" << std::endl;
                exit(1);
            }
            exit(0);
        }
        *ppid = child_pid;
        close(pipe_fds[1]);
        return pipe_fds[0];
    }
};

typedef std::vector<inflater *> inflaters_t;
static inflaters_t *build_inflaters()
{
    inflaters_t *output = new inflaters_t();

    // gzip
    output->push_back(new inflater(".gz", "gunzip -c '%s'"));
    // zip
    output->push_back(new inflater(".zip", "unzip -p '%s'"));
    // bz2
    output->push_back(new inflater(".bz2", "bunzip2 -c '%s'"));
    // xz
    output->push_back(new inflater(".xz", "unxz -c '%s'"));
    // lzma
    output->push_back(new inflater(".lzma", "unlzma -c '%s'"));

    return output;
}

#define HAVE_INFLATER
#endif

// https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.c#L611
#ifndef _WIN32
/* Drop root privileges and chroot if necessary */
static void
droproot(tcpdemux &demux,const char *username, const char *chroot_dir)
{
    struct passwd *pw = NULL;

    if (chroot_dir && !username) {
        fprintf(stderr, "%s: Chroot without dropping root is insecure\n",
                program_name);
        exit(1);
    }

    pw = getpwnam(username);
    if (pw) {
        /* Begin tcpflow add */
        if(demux.xreport){
            const char *outfilename = demux.xreport->get_outfilename().c_str();
            if(chown(outfilename,pw->pw_uid,pw->pw_gid)){
                fprintf(stderr, "%s: Coudln't change owner of '%.64s' to %s (uid %d): %s\n",
                        program_name, outfilename, username, pw->pw_uid, strerror(errno));
                exit(1);
            }
        }
        /* end tcpflow add */
        if (chroot_dir) {
            if (chroot(chroot_dir) != 0 || chdir ("/") != 0) {
                fprintf(stderr, "%s: Couldn't chroot/chdir to '%.64s': %s\n",
                        program_name, chroot_dir, pcap_strerror(errno));
                exit(1);
            }
        }
#ifdef HAVE_LIBCAP_NG
        {
            int ret = capng_change_id(pw->pw_uid, pw->pw_gid, CAPNG_NO_FLAG);
            if (ret < 0) {
                fprintf(stderr, "error : ret %d\n", ret);
            } else {
                fprintf(stderr, "dropped privs to %s\n", username);
            }
        }
#else
        if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
            setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
            fprintf(stderr, "%s: Couldn't change to '%.32s' uid=%lu gid=%lu: %s\n",
                    program_name, username,
                    (unsigned long)pw->pw_uid,
                    (unsigned long)pw->pw_gid,
                    pcap_strerror(errno));
            exit(1);
        }
        else {
            fprintf(stderr, "dropped privs to %s\n", username);
        }
#endif /* HAVE_LIBCAP_NG */
    }
    else {
        fprintf(stderr, "%s: Couldn't find user '%.32s'\n",
                program_name, username);
        exit(1);
    }
#ifdef HAVE_LIBCAP_NG
    /* We don't need CAP_SETUID, CAP_SETGID and CAP_SYS_CHROOT any more. */
    capng_updatev(
                  CAPNG_DROP,
                  (capng_type_t)(CAPNG_EFFECTIVE | CAPNG_PERMITTED),
                  CAP_SETUID,
                  CAP_SETGID,
                  CAP_SYS_CHROOT,
                  -1);
    capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */

}
#endif /* _WIN32 */

/**
 * Perform the droproot operation for tcpflow. This needs to be called immediately after pcap_open()
 */
void tcpflow_droproot(tcpdemux &demux)
{
    if (tcpflow_droproot_username){
        droproot(demux,tcpflow_droproot_username,tcpflow_chroot_dir);
    }
}

/*
 * process an input file or device
 * May be repeated.
 * If start is false, do not initiate new connections
 * Return 0 on success or -1 on error
 */
#ifdef HAVE_INFLATER
static inflaters_t *inflaters = 0;
#endif
static int process_infile(tcpdemux &demux,const std::string &expression,std::string &device,const std::string &infile)
{
    char error[PCAP_ERRBUF_SIZE];
    int dlt=0;
    pcap_handler handler;
    int waitfor = -1;
    int pipefd = -1;

#ifdef HAVE_INFLATER
    if(inflaters==0) inflaters = build_inflaters();
#endif

    if (infile!=""){
        std::string file_path = infile;
        // decompress input if necessary
#ifdef HAVE_INFLATER
        for(inflaters_t::const_iterator it = inflaters->begin(); it != inflaters->end(); it++) {
            if((*it)->appropriate(infile)) {
                pipefd = (*it)->invoke(infile, &waitfor);
                if(pipefd < 0) {
                    std::cerr << "decompression of '" << infile << "' failed: " << strerror (errno) << std::endl;
                    exit(1);
                }
                file_path = ssprintf("/dev/fd/%d", pipefd);
                if(access(file_path.c_str(), R_OK)) {
                    std::cerr << "decompression of '" << infile << "' is not available on this system" << std::endl;
                    exit(1);
                }
                break;
            }
        }
#endif
	if ((pd = pcap_open_offline(file_path.c_str(), error)) == NULL){	/* open the capture file */
	    die("%s", error);
	}
        tcpflow_droproot(demux);        // drop root if requested
	dlt = pcap_datalink(pd);	/* get the handler for this kind of packets */
	handler = find_handler(dlt, infile.c_str());
    } else {
	/* if the user didn't specify a device, try to find a reasonable one */
    if (device.empty()){
#ifdef HAVE_PCAP_FINDALLDEVS
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs = 0;
        if (pcap_findalldevs(&alldevs,errbuf)){
            die("%s", errbuf);
        }

        if (alldevs == 0) {
            die("found 0 devices, maybe you don't have permissions, switch to root or equivalent user instead.");
        }

        device.assign(alldevs[0].name);
        pcap_freealldevs(alldevs);
#else
        const char* dev = pcap_lookupdev(error);
        if (dev == NULL)
            die("%s", error);

        device.assign(dev);
#endif
    }

	/* make sure we can open the device */
	if ((pd = pcap_open_live(device.c_str(), SNAPLEN, !opt_no_promisc, packet_buffer_timeout, error)) == NULL){
	    die("%s", error);
	}
        tcpflow_droproot(demux);                     // drop root if requested
	/* get the handler for this kind of packets */
	dlt = pcap_datalink(pd);
	handler = find_handler(dlt, device.c_str());
    }

    DEBUG(20) ("filter expression: '%s'",expression.c_str());

    /* install the filter expression in libpcap */
    struct bpf_program	fcode;
    if (pcap_compile(pd, &fcode, expression.c_str(), 1, 0) < 0){
	die("%s", pcap_geterr(pd));
    }

    if (pcap_setfilter(pd, &fcode) < 0){
	die("%s", pcap_geterr(pd));
    }

    /* initialize our flow state structures */

    /* set up signal handlers for graceful exit (pcap uses onexit to put
     * interface back into non-promiscuous mode
     */
    portable_signal(SIGTERM, terminate);
    portable_signal(SIGINT, terminate);
#ifdef SIGHUP
    portable_signal(SIGHUP, terminate);
#endif

    /* start listening or reading from the input file */
    if (infile == "") DEBUG(1) ("listening on %s", device.c_str());
    int pcap_retval = pcap_loop(pd, -1, handler, (u_char *)tcpdemux::getInstance());

    if (pcap_retval < 0 && pcap_retval != -2){
	DEBUG(1) ("%s: %s", infile.c_str(),pcap_geterr(pd));
	return -1;
    }
    pcap_close (pd);
#ifdef HAVE_FORK
    if (waitfor != -1) {
        wait (0);
    }
    if (pipefd != -1) {
        close (pipefd);
    }
#endif

    return 0;
}


/* be_hash. Currently this just returns the MD5 of the sbuf,
 * but eventually it will allow the use of different hashes.
 */
static std::string be_hash_name("md5");
static std::string be_hash_func(const uint8_t *buf,size_t bufsize)
{
    if(be_hash_name=="md5" || be_hash_name=="MD5"){
        return dfxml::md5_generator::hash_buf(buf,bufsize).hexdigest();
    }
    if(be_hash_name=="sha1" || be_hash_name=="SHA1" || be_hash_name=="sha-1" || be_hash_name=="SHA-1"){
        return dfxml::sha1_generator::hash_buf(buf,bufsize).hexdigest();
    }
    if(be_hash_name=="sha256" || be_hash_name=="SHA256" || be_hash_name=="sha-256" || be_hash_name=="SHA-256"){
        return dfxml::sha256_generator::hash_buf(buf,bufsize).hexdigest();
    }
    std::cerr << "Invalid hash name: " << be_hash_name << "\n";
    std::cerr << "This version of bulk_extractor only supports MD5, SHA1, and SHA256\n";
    exit(1);
}
static feature_recorder_set::hash_def be_hash(be_hash_name,be_hash_func);


int main(int argc, char *argv[])
{
    program_name = argv[0];
    int opt_help = 0;
    int opt_Help = 0;
    feature_recorder::set_main_threadid();
    sbuf_t::set_map_file_delimiter(""); // no delimiter on carving
#ifdef BROKEN
    std::cerr << "WARNING: YOU ARE USING AN EXPERIMENTAL VERSION OF TCPFLOW \n";
    std::cerr << "THAT DOES NOT WORK PROPERLY. PLEASE USE A RELEASE DOWNLOADED\n";
    std::cerr << "FROM http://digitalcorpora.org/downloads/tcpflow\n";
    std::cerr << "\n";
#endif

    bool opt_enable_report = true;
    bool force_binary_output = false;
    std::string device;             // default device
    const char *lockname = 0;
    std::string reportfilename;
    std::vector<std::string> Rfiles;	// files for finishing
    std::vector<std::string> rfiles;	// files to read
    tcpdemux &demux = *tcpdemux::getInstance();			// the demux object we will be using.
    std::string command_line = dfxml_writer::make_command_line(argc,argv);
    std::string opt_unk_packets;
    bool opt_quiet = false;

    /* Set up debug system */
    progname = argv[0];
    init_debug(progname,1);

    /* Make sure that the system was compiled properly */
    if(sizeof(struct be13::ip4)!=20 || sizeof(struct be13::tcphdr)!=20){
	fprintf(stderr,"COMPILE ERROR.\n");
	fprintf(stderr,"  sizeof(struct ip)=%d; should be 20.\n", (int)sizeof(struct be13::ip4));
	fprintf(stderr,"  sizeof(struct tcphdr)=%d; should be 20.\n", (int)sizeof(struct be13::tcphdr));
	fprintf(stderr,"CANNOT CONTINUE\n");
	exit(1);
    }

    bool trailing_input_list = false;
    int arg;
    while ((arg = getopt_long(argc, argv, "aA:Bb:cCd:DE:e:E:F:f:gHhIi:lL:m:o:pqR:r:S:sT:U:Vvw:x:X:z:ZK0J", longopts, NULL)) != EOF) {
	switch (arg) {
	case 'a':
	    demux.opt.post_processing = true;
	    demux.opt.opt_md5 = true;
            be13::plugin::scanners_enable_all();
	    break;

	case 'A':
	    fprintf(stderr,"-AH has been deprecated. Just use -a\n");
	    break;

	case 'b':
	    demux.opt.max_bytes_per_flow = atoi(optarg);
	    if(debug > 1) {
		std::cout << "capturing max of " << demux.opt.max_bytes_per_flow << " bytes per flow." << std::endl;
	    }
	    break;
	case 'B':
            force_binary_output = true;
	    demux.opt.output_strip_nonprint  = false;	DEBUG(10) ("converting non-printable characters to '.'");
	    break;
	case 'C':
	    demux.opt.console_output  = true;	DEBUG(10) ("printing packets to console only");
	    demux.opt.suppress_header = 1;	DEBUG(10) ("packet header dump suppressed");
	    break;
	case 'c':
	    demux.opt.console_output = true;	DEBUG(10) ("printing packets to console only");
	    break;
    case '0':
	    demux.opt.console_output_nonewline = true;
	    break;
	case 'd':
	    if ((debug = atoi(optarg)) < 0) {
		debug = DEFAULT_DEBUG_LEVEL;
		DEBUG(1) ("warning: -d flag with 0 debug level '%s'", optarg);
	    }
	    break;
    case 'D':
        demux.opt.output_hex = true;DEBUG(10) ("Console output in hex");
	    demux.opt.output_strip_nonprint = false;	DEBUG(10) ("Will not convert non-printablesto '.'");
        break;
	case 'E':
	    be13::plugin::scanners_disable_all();
	    be13::plugin::scanners_enable(optarg);
	    break;
        case 'e':
            be13::plugin::scanners_enable(optarg);
            demux.opt.post_processing = true; // enable post processing if anything is turned on
            break;
	case 'F':
	    for(const char *cc=optarg;*cc;cc++){
		switch(*cc){
		case 'c': replace(flow::filename_template,"%c","%C"); break;
                case 'k': flow::filename_template = "%K/" + flow::filename_template; break;
                case 'm': flow::filename_template = "%M000-%M999/%M%K/" + flow::filename_template; break;
                case 'g': flow::filename_template = "%G000000-%G999999/%G%M000-%G%M999/%G%M%K/" + flow::filename_template; break;
		case 't': flow::filename_template = "%tT" + flow::filename_template; break;
		case 'T': flow::filename_template = "%T"  + flow::filename_template; break;
		case 'X': demux.opt.store_output = false;break;
		case 'M': demux.opt.opt_md5 = true;break;
		default:
		    fprintf(stderr,"-F invalid format specification '%c'\n",*cc);
		}
	    }
	    break;
	case 'f':
        {
            int mnew = atoi(optarg);
            DEBUG(1)("changing max_fds from %d to %d",demux.max_fds,mnew);
            demux.max_fds = mnew;
	    break;
        }
    case 'i': device = std::string(optarg); break;
 	case 'I':
 		DEBUG(10) ("creating packet index files");
 		demux.opt.output_packet_index = true;
 		break;
	case 'g':
	    demux.opt.use_color  = 1;
	    DEBUG(10) ("using colors");
	    break;
        case 'l': trailing_input_list = true; break;
    case 'J':
        demux.opt.output_json = true;
        break;
    case 'K':;
        demux.opt.output_pcap = true;
        demux.alter_processing_core();
        break;
	case 'L': lockname = optarg; break;
	case 'm':
	    demux.opt.max_seek = atoi(optarg);
	    DEBUG(10) ("max_seek set to %d",demux.opt.max_seek); break;
	case 'o':
            demux.outdir = optarg;
            flow::outdir = optarg;
            break;
	case 'p': opt_no_promisc = true; DEBUG(10) ("NOT turning on promiscuous mode"); break;
        case 'q': opt_quiet = true; break;
	case 'R': Rfiles.push_back(optarg); break;
	case 'r': rfiles.push_back(optarg); break;
        case 'S':
	    {
		std::vector<std::string> params = split(optarg,'=');
		if(params.size()!=2){
		    std::cerr << "Invalid paramter: " << optarg << "\n";
		    exit(1);
		}
		be_config.namevals[params[0]] = params[1];
		continue;
	    }

	case 's':
            demux.opt.output_strip_nonprint = 1; DEBUG(10) ("converting non-printable characters to '.'");
            break;
	case 'T':
            flow::filename_template = optarg;
            if(flow::filename_template.find("%c")==std::string::npos){
                flow::filename_template += std::string("%C%c"); // append %C%c if not present
            }
            break;
        case 'U': tcpflow_droproot_username = optarg; break;
	case 'V': std::cout << PACKAGE_NAME << " " << PACKAGE_VERSION << "\n"; exit (1);
	case 'v': debug = 10; break;
        case 'w': opt_unk_packets = optarg;break;
	case 'x': be13::plugin::scanners_disable(optarg);break;
	case 'X': reportfilename = optarg;break;
        case 'z': tcpflow_chroot_dir = optarg; break;
	case 'Z': demux.opt.gzip_decompress = 0; break;
	case 'H': opt_Help += 1; break;
	case 'h': opt_help += 1; break;
	default:
	    DEBUG(1) ("error: unrecognized switch '%c'", arg);
	    opt_help += 1;
	    break;
	}
    }

    if(tcpflow_chroot_dir && !tcpflow_droproot_username){
        err(1,"-z option requires -U option");
    }

    argc -= optind;
    argv += optind;


    /* Load all the scanners and enable the ones we care about */
    scanner_info si;
    si.config = &be_config;

    si.get_config("enable_report",&opt_enable_report,"Enable report.xml");
    be13::plugin::load_scanners(scanners_builtin,be_config);

    if(opt_Help){
        be13::plugin::info_scanners(true,true,scanners_builtin,'e','x');
        exit(0);
    }

    if(opt_help) {
        usage(opt_help);
        exit(0);
    }


    if(demux.opt.post_processing && !demux.opt.store_output){
        std::cerr << "ERROR: post_processing currently requires storing output.\n";
        exit(1);
    }

    if(demux.opt.opt_md5) be13::plugin::scanners_enable("md5");
    be13::plugin::scanners_process_enable_disable_commands();

    /* If there is no report filename, call it report.xml in the output directory */
    if( reportfilename.size()==0 ){
	reportfilename = demux.outdir + "/" + DEFAULT_REPORT_FILENAME;
    }

    /* remaining arguments are either an input list (-l flag) or a pcap expression (default) */
    std::string expression = "";
    if(trailing_input_list) {
        for(int ii = 0; ii < argc; ii++) {
            rfiles.push_back(argv[ii]);
        }
    }
    else {
        /* get the user's expression out of remainder of the arg... */
        for(int i=0;i<argc;i++){
            if(expression.size()>0) expression+=" ";
            expression += argv[i];
        }
    }

    /* More option processing */

    /* was a semaphore provided for the lock? */
    if(lockname){
#if defined(HAVE_SEMAPHORE_H) && defined(HAVE_PTHREAD_H)
	semlock = sem_open(lockname,O_CREAT,0777,1); // get the semaphore
#else
	fprintf(stderr,"%s: attempt to create lock pthreads not present\n",argv[0]);
	exit(1);
#endif
    }

    if(force_binary_output) demux.opt.output_strip_nonprint = false;
    /* make sure outdir is a directory. If it isn't, try to make it.*/
    struct stat stbuf;
    if(stat(demux.outdir.c_str(),&stbuf)==0){
	if(!S_ISDIR(stbuf.st_mode)){
	    std::cerr << "outdir is not a directory: " << demux.outdir << "\n";
	    exit(1);
	}
    } else {
	if(MKDIR(demux.outdir.c_str(),0777)){
	    std::cerr << "cannot create " << demux.outdir << ": " << strerror(errno) << "\n";
	    exit(1);
	}
    }

    std::string input_fname;
    if(rfiles.size() > 0) {
        input_fname = rfiles.at(0);
        if(rfiles.size() > 1) {
            input_fname += ssprintf(" + %d more", rfiles.size() - 1);
        }
    }

    /* report file specified? If so, open it.
     * Note: If we are going to chroot, we need apply the chroot prefix also,
     * but we need to open the file *now*.
     */
    if(reportfilename.size()>0 && opt_enable_report){
        if (tcpflow_chroot_dir){
            reportfilename = std::string(tcpflow_chroot_dir) + std::string("/") + reportfilename;
        }
        std::cerr << "reportfilename: " << reportfilename << "\n";
	xreport = new dfxml_writer(reportfilename,false);
	dfxml_create(*xreport,command_line);
	demux.xreport = xreport;
    }
    if(opt_unk_packets.size()>0){
        if(input_fname.size()==0){
            std::cerr << "currently the -w option requires the -r option\n";
            exit(1);
        }
        if(access(input_fname.c_str(),R_OK)) die("cannot read: %s: %s",input_fname.c_str(),strerror(errno));
        demux.save_unk_packets(opt_unk_packets,input_fname);
    }


    /* Debug prefix set? */
    std::string debug_prefix=progname;
    si.get_config("debug-prefix",&debug_prefix,"Prefix for debug output");
    init_debug(debug_prefix.c_str(),0);

    DEBUG(10) ("%s version %s ", PACKAGE_NAME, PACKAGE_VERSION);

    const char *name = device.c_str();
    if(input_fname.size()>0) name=input_fname.c_str();
    if(name==0) name="<default>";

    feature_file_names_t feature_file_names;
    be13::plugin::get_scanner_feature_file_names(feature_file_names);
    feature_recorder_set fs(feature_recorder_set::NO_ALERT,be_hash,name,demux.outdir);
    fs.init(feature_file_names);
    the_fs   = &fs;
    demux.fs = &fs;

    si.get_config("tdelta",&datalink_tdelta,"Time offset for packets");
    si.get_config("packet-buffer-timeout", &packet_buffer_timeout, "Time in milliseconds between each callback from libpcap");

    /* Record the configuration */
    if(xreport){
        xreport->push("configuration");
        xreport->pop();			// configuration
        xreport->xmlout("tdelta",datalink_tdelta);
    }



    /* Process r files and R files */
    int exit_val = 0;
    if(xreport){
        xreport->push("configuration");
    }
    if(rfiles.size()==0 && Rfiles.size()==0){
	/* live capture */
	demux.start_new_connections = true;
        int err = process_infile(demux,expression,device,"");
        if (err < 0) {
            exit_val = 1;
        }
        input_fname = device;
    }
    else {
	/* first pick up the new connections with -r */
	demux.start_new_connections = true;
	for(std::vector<std::string>::const_iterator it=rfiles.begin();it!=rfiles.end();it++){
	    int err = process_infile(demux,expression,device,*it);
	    if (err < 0) {
	        exit_val = 1;
	    }
	}
	/* now pick up the outstanding connection with -R, but don't start new connections */
	demux.start_new_connections = false;
	for(std::vector<std::string>::const_iterator it=Rfiles.begin();it!=Rfiles.end();it++){
	    int err = process_infile(demux,expression,device,*it);
	    if (err < 0) {
	        exit_val = 1;
	    }
	}
    }

    /* -1 causes pcap_loop to loop forever, but it finished when the input file is exhausted. */

    DEBUG(2)("Open FDs at end of processing:      %d",(int)demux.open_flows.size());
    DEBUG(2)("demux.max_open_flows:               %d",(int)demux.max_open_flows);
    DEBUG(2)("Flow map size at end of processing: %d",(int)demux.flow_map.size());
    DEBUG(2)("Flows seen:                         %d",(int)demux.flow_counter);

    int open_fds = (int)demux.open_flows.size();
    int flow_map_size = (int)demux.flow_map.size();

    demux.remove_all_flows();	// empty the map to capture the state
    std::stringstream ss;
    be13::plugin::phase_shutdown(fs,xreport ? &ss : 0);

    /*
     * Note: funny formats below are a result of mingw problems with PRId64.
     */
    const std::string total_flow_processed("Total flows processed: %" PRId64);
    const std::string total_packets_processed("Total packets processed: %" PRId64);

    DEBUG(2)(total_flow_processed.c_str(),demux.flow_counter);
    DEBUG(2)(total_packets_processed.c_str(),demux.packet_counter);

    if(xreport){
        xreport->pop();                 // fileobjects
        xreport->xmlout("summary",ss.str(),"",false);
        xreport->xmlout("open_fds_at_end",open_fds);
        xreport->xmlout("max_open_flows",demux.max_open_flows);
        xreport->xmlout("total_flows",demux.flow_counter);
        xreport->xmlout("flow_map_size",flow_map_size);
        xreport->xmlout("total_packets",demux.packet_counter);
	xreport->add_rusage();
	xreport->pop();                 // bulk_extractor
	xreport->close();
	delete xreport;
    }

    if(demux.flow_counter > tcpdemux::WARN_TOO_MANY_FILES){
        if(!opt_quiet){
            /* Start counting how many files we have in the output directory.
             * If we find more than 10,000, print the warning, and keep counting...
             */
            uint64_t filecount=0;
            DIR *dirp = opendir(demux.outdir.c_str());
            if(dirp){
                struct dirent *dp=0;
                while((dp=readdir(dirp))!=NULL){
                    filecount++;
                    if(filecount==10000){
                        std::cerr << "*** tcpflow WARNING:\n";
                        std::cerr << "*** Modern operating systems do not perform well \n";
                        std::cerr << "*** with more than 10,000 entries in a directory.\n";
                        std::cerr << "***\n";
                    }
                }
                closedir(dirp);
            }
            if(filecount>=10000){
                std::cerr << "*** tcpflow created " << filecount
                          << " files in output directory " << demux.outdir << "\n";
                std::cerr << "***\n";
                std::cerr << "*** Next time, specify command-line options: -Fk , -Fm , or -Fg \n";
                std::cerr << "*** This will automatically bin output into subdirectories.\n";
                std::cerr << "*** type 'tcpflow -hhh' for more information.\n";
            }
        }
    }

    exit(exit_val);                     // return(0) causes crash on Windows
}
