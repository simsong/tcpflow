TCPFLOW 1.5.0
=============
Downloads directory: http://digitalcorpora.org/downloads/tcpflow/

Installation
------------

Most common GNU/Linux distributions ship tcpflow in their repositories. So on Debian/Ubuntu/etc you can say

    sudo apt-get install tcpflow

and on Fedora/RedHat/CentOS/etc you can say

    sudo dnf install tcpflow

And that's it. If this isn't good-enough for whatever reason, you can build from source:

Building from source
--------------------

To compile for Linux

Be sure you have the necessary precursors. There are files in the root directory that will do this for you, depending on your host operating system:

CONFIGURE_ARCH_17_8.sh
CONFIGURE_FEDORA_18.sh
CONFIGURE_FEDORA_26.sh
CONFIGURE_UBUNTU_16_04.sh

Depending on your OS, just:

    # sudo bash CONFIGURE_<YOUROS>.sh

Once you have configured your OS, compile and install with:

    ./configure
    make
    sudo make install

If you want do download the development tree with git, be sure to do a *complete* checkout with `--recursive` and then run `bootstrap.sh`, `configure` and `make`:

    git clone --recursive https://github.com/simsong/tcpflow.git
    cd tcpflow
    bash bootstrap.sh
    ./configure
    make
    sudo make install  


To download and compile for Amazon AMI:

    ssh ec2-user@<your ec2 instance>
    sudo bash yum -y install git make gcc-c++ automake autoconf boost-devel cairo-devel libpcap-devel openssl-devel zlib-devel
    git clone --recursive https://github.com/simsong/tcpflow.git
    sh bootstrap.sh


To Compile for Windows with mingw on Fedora Core:
    
    yum -y install mingw64-gcc mingw64-gcc-c++ mingw64-boost mingw64-cairo mingw64-zlib
    mingw64-configure
    make

To use CMake, see detailed instructions: [cmake/README.md](./cmake/README.md)

Build RPM
---------

From a clean repository as normal user (not root):

    ./bootstrap.sh     # Generates the file ./configure
    ./configure        # Generates the file tcpflow.spec
    rpmbuild -bb tcpflow.spec --build-in-place

Check the specfile and resulted RPM:

    rpmlint tcpflow.spec
    rpmlint ~/rpmbuild/RPMS/x86_64/tcpflow-....rpm

Install:

    sudo dnf install ~/rpmbuild/RPMS/x86_64/tcpflow-....rpm


Introduction To tcpflow
=======================

tcpflow is a program that captures data transmitted as part of TCP
connections (flows), and stores the data in a way that is convenient
for protocol analysis and debugging.  Each TCP flow is stored in its
own file. Thus, the typical TCP flow will be stored in two files, one
for each direction. tcpflow can also process stored 'tcpdump' packet
flows.

tcpflow stores all captured data in files that have names of the form:

       [timestampT]sourceip.sourceport-destip.destport[--VLAN][cNNNN]

where:
  timestamp is an optional timestamp of the time that the first packet was seen
  T is a delimiter that indicates a timestamp was provided
  sourceip is the source IP address
  sourceport is the source port
  destip is the destination ip address
  destport is the destination port
  VLAN is the VLAN port
  c is a delimiter indicating that multiple connections are present
  NNNN is a connection counter, when there are multiple connections with 
      the same [time]/sourceip/sourceport/destip/destport combination.  
      Note that connection counting rarely happens when timestamp prefixing is performed.

HERE are some examples:

       128.129.130.131.02345-010.011.012.013.45103

  The contents of the above file would be data transmitted from
  host 128.129.131.131 port 2345, to host 10.11.12.13 port 45103.

       128.129.130.131.02345-010.011.012.013.45103c0005

  The sixth connection from 128.129.131.131 port 2345, to host 10.11.12.13 port 45103.

       1325542703T128.129.130.131.02345-010.011.012.013.45103

  A connection from 128.129.131.131 port 2345, to host 10.11.12.13 port 45103, that started on
  at 5:19pm (-0500) on January 2, 2012
  
       128.129.130.131.02345-010.011.012.013.45103--3

  A connection from 128.129.131.131 port 2345, to host 10.11.12.13
  port 45103 that was seen on VLAN port 3. 
   

You can change the template that is used to create filenames with the
-F and -T options.  If a directory appears in the template the directory will be automatically created.

If you use the -a option, tcpflow will automatically interpret HTTP responses.

       If the output file is
          208.111.153.175.00080-192.168.001.064.37314,

       Then the post-processing will create the files:
          208.111.153.175.00080-192.168.001.064.37314-HTTP
          208.111.153.175.00080-192.168.001.064.37314-HTTPBODY

       If the HTTPBODY was compressed with GZIP, you may get a 
       third file as well:

          208.111.153.175.00080-192.168.001.064.37314-HTTPBODY-GZIP

       Additional information about these streams, such as their MD5
       hash value, is also written to the DFXML file


tcpflow is similar to 'tcpdump', in that both process packets from the
wire or from a stored file. But it's different in that it reconstructs
the actual data streams and stores each flow in a separate file for
later analysis.

tcpflow understands sequence numbers and will correctly reconstruct
data streams regardless of retransmissions or out-of-order
delivery. However, tcpflow currently does not understand IP fragments; flows
containing IP fragments will not be recorded properly.

tcpflow can output a summary report file in DFXML format. This file
includes information about the system on which the tcpflow program was
compiled, where it was run, and every TCP flow, including source and
destination IP addresses and ports, number of bytes, number of
packets, and (optionally) the MD5 hash of every bytestream. 

tcpflow uses the LBL Packet Capture Library (available at
ftp://ftp.ee.lbl.gov/libpcap.tar.Z) and therefore supports the same
rich filtering expressions that programs like 'tcpdump' support.  It
should compile under most popular versions of UNIX; see the INSTALL
file for details.

What use is it?
---------------

tcpflow is a useful tool for understanding network packet flows and
performing network forensics. Unlike programs such as WireShark, which
show lots of packets or a single TCP connection, tcpflow can show
hundreds, thousands, or hundreds of thousands of TCP connections in
context. 

A common use of tcpflow is to reveal the contents of HTTP
sessions. Using tcpflow you can reconstruct web pages downloaded over
HTTP. You can even extract malware delivered as 'drive-by downloads.'

Jeremy Elson originally wrote this program to capture the data being
sent by various programs that use undocumented network protocols in an
attempt to reverse engineer those protocols.  RealPlayer (and most
other streaming media players), ICQ, and AOL IM are good examples of
this type of application.  It was later used for HTTP protocol
analysis.

Simson Garfinkel founded Sandstorm Enterprises in 1998. Sandstorm
created a program similar to tcpflow called TCPDEMUX and another
version of the program called NetIntercept. Those programs are
commercial. After Simson left Sandstorm he had need for a tcp flow
reassembling program. He found tcpflow and took over its maintenance.

Bugs
----

Please enter bugs on the [github issue tracker](https://github.com/simsong/tcpflow/issues?state=open)

tcpflow currently does not understand IP fragments.  Flows containing
IP fragments will not be recorded correctly. IP fragmentation is
increasingly a rare event, so this does not seem to be a significant problem.

RECOMMENDED CITATION
====================
If you are writing an article about tcpflow, please cite our technical report:
* Passive TCP Reconstruction and Forensic Analysis with tcpflow, Simson Garfinkel and Michael Shick, Naval Postgraduate School Technical Report NPS-CS-13-003, September 2013. https://calhoun.nps.edu/handle/10945/36026

MAINTAINER
==========
Simson L. Garfinkel <simsong@acm.org>

TCPFLOW 1.6 STATUS REPORT
=========================
I continue to port bulk_extractor, tcpflow, be13_api and dfxml to modern C++. After surveying the standards I’ve decided to go with C++17 and not C++14, as support for 17 is now widespread. (I probably don’t need 20). I am sticking with autotools, although there seems a strong reason to move to CMake. I am keeping be13_api and dfxml as a modules that are included, python-style, rather than making them stand-alone libraries that are linked against. I’m not 100% sure that’s the correct decision, though.

The project is taking longer than anticipated because I am also doing a general code refactoring. The main thing that is taking time is figuring out how to detangle all of the C++ objects having to do with parser options and configuration. 

Given that tcpflow and bulk_extractor both use be13_api, my attention has shifted to using tcpflow to get be13_api operational, as it is a simpler program. I’m about three quarters of the way through now. I anticipate having something finished before the end of 2020.

--- Simson Garfinkel, October 18, 2020

ACKNOWLEDGEMENTS
================
Thanks to: 
* Jeffrey Pang, for the radiotap implementation
* Doug Madory, for the  Wifi parser
* Jeremy Elson, for the original idea and initial tcp/ip implementation



