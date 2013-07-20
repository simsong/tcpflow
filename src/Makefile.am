# Programs that we compile:
bin_PROGRAMS = tcpflow

AM_CPPFLAGS = -I${top_srcdir}/src/be13_api

include dfxml/src/Makefile.defs
include be13_api/Makefile.defs

# http://stackoverflow.com/questions/11438613/conditional-subdir-objects
AUTOMAKE_OPTIONS = subdir-objects

NETVIZ = \
	netviz/plot_view.cpp \
	netviz/plot_view.h \
	netviz/time_histogram_view.cpp \
	netviz/time_histogram_view.h \
	netviz/time_histogram.cpp \
	netviz/time_histogram.h \
	netviz/address_histogram_view.cpp \
	netviz/address_histogram_view.h \
	netviz/address_histogram.cpp \
	netviz/address_histogram.h \
	netviz/port_histogram_view.cpp \
	netviz/port_histogram_view.h \
	netviz/port_histogram.cpp \
	netviz/port_histogram.h \
	netviz/packetfall.cpp \
	netviz/packetfall.h \
	netviz/net_map.cpp \
	netviz/net_map.h \
	netviz/legend_view.cpp \
	netviz/legend_view.h \
	netviz/one_page_report.cpp \
	netviz/one_page_report.h

WIFI = 	wifi_datalink.cpp \
	wifipcap.cpp \
	wifipcap.h \
	cpack.h \
	cpack.cpp \
	uni/ethertype.h \
	uni/extract.h \
	uni/ieee802_11.h \
	uni/ieee802_11_radio.h \
	uni/llc.h \
	uni/oui.h \
	uni/packet-ieee80211.h 


tcpflow_SOURCES = \
	$(DFXML_WRITER) $(NETVIZ) $(BE13_API) $(WIFI) \
	datalink.cpp flow.cpp \
	tcpflow.cpp \
	tcpip.h tcpip.cpp \
	tcpdemux.h tcpdemux.cpp \
	tcpflow.h util.cpp \
	scan_md5.cpp \
	scan_http.cpp \
	scan_tcpdemux.cpp \
	scan_netviz.cpp \
	pcap_writer.h \
	iptree.h \
	http-parser/http_parser.c \
	http-parser/http_parser.h \
	mime_map.cpp \
	mime_map.h 

EXTRA_DIST =\
	http-parser/AUTHORS \
	http-parser/CONTRIBUTIONS \
	http-parser/LICENSE-MIT \
	http-parser/Makefile \
	http-parser/README.md \
	http-parser/http_parser.gyp 

testiph: tcpflow
	echo Testing the IP histogram
	for i in 100 1000 10000 ; \
		do /bin/rm -f test-$$i out-$$i.txt ; \
		./tcpflow -o test1 -S iphtest=1 -S iphtrim=$$i -r /corp/nps/packets/2008-nitroba/nitroba.pcap > iphtest-nitroba-$$i.txt ; \
		done
	diff ../tests/iphtest-nitroba-100.txt iphtest-nitroba-100.txt 
	diff ../tests/iphtest-nitroba-1000.txt iphtest-nitroba-1000.txt 
	diff ../tests/iphtest-nitroba-10000.txt iphtest-nitroba-10000.txt 
	echo iptree appears okay.
