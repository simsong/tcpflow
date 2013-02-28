
Title:   Wifipcap Library
Authors: Jeff Pang <jeffpang@cs.cmu.edu>


Description:
============

A simple C++ wrapper around libpcap that allows applications to
selectively demultiplex 802.11 frames, and the most common layer 2 and
layer 3 protocols contained within them. Basically, the wifipcap
library handles all the parsing of 802.11 frames (and/or layer 2/3
packets) from the pcap file (or stream).

Most of the code is derived from tcpdump.

Linux: Requires libpcap >= 0.9.4 on Linux.

Windows: Requires WinPcap >= 4.0.2 and AirPcap for 802.11 capture
See: http://www.cacetech.com/support/downloads.htm

Usage:
======

For an overview see wifipcap.h. For an example, see sample.cpp.

(0) Compile wifipcap. 

    In Linux:
    Enter this directory and type:
   
    make

    In Windows:
    Open wifipcap.sln in Visual Studio and build it.
    You will need to have the winpcap include and library files
    in the appropriate search paths.

(1) Include the header "wifipcap.h" in your application C++ file(s).

(2) Implement a subclass of WifipcapCallbacks. This class has one
    member function for each type of 802.11 frame and layer 2/3
    packets. Each of these functions will be called as a frame/packet
    is parsed.

(3) Create an instance of Wifipcap with either a pcap trace file or
    a live device to capture packets from.

(4) Call Wifipcap::Run with your instance of WifipcapCallbacks.

(5) Compile your program linking to libpcap and wifipcap.a. 

    On Linux:
    g++ -o myprogram myprogram.c /path/to/wifipcap.a -lpcap

    On Windows:
    Link the following libraries: 
    wpcap.lib ws2_32.lib WINMM.LIB wifipcap.lib 

    Make sure wifipcap.lib is in the library path.
