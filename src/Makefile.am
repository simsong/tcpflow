# Programs that we compile:
bin_PROGRAMS = tcpflow

AM_CPPFLAGS = -I${top_srcdir}/src/be13_api

# bulk_extractor 1.3 API:

BE13_API = \
	be13_api/bulk_extractor_i.h \
	be13_api/cppmutex.h \
	be13_api/feature_recorder.cpp \
	be13_api/feature_recorder.h \
	be13_api/feature_recorder_set.cpp \
	be13_api/feature_recorder_set.h \
	be13_api/md5.c \
	be13_api/md5.h \
	be13_api/net_ethernet.h \
	be13_api/pcap_fake.h \
	be13_api/pcap_fake.cpp \
	be13_api/plugin.cpp\
	be13_api/beregex.cpp \
	be13_api/beregex.h \
	be13_api/sbuf.cpp \
	be13_api/sbuf.h \
	be13_api/sbuf_flex_scanner.h \
	be13_api/sbuf_private.h \
	be13_api/sbuf_stream.h \
	be13_api/sbuf_stream.cpp \
	be13_api/utf8.h \
	be13_api/utf8/checked.h \
	be13_api/utf8/core.h \
	be13_api/utf8/unchecked.h \
	be13_api/xml.cpp \
	be13_api/xml.h \
	be13_api/unicode_escape.h \
	be13_api/unicode_escape.cpp \
	be13_api/utils.h \
	be13_api/utils.cpp

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
	netviz/one_page_report.cpp \
	netviz/one_page_report.h

WIFI = 	wifipcap.h \
	wifipcap.cpp \
	wifi_datalink.cpp \
	ieee802_11_radio.h \
	cpack.cpp 

tcpflow_SOURCES = \
	$(NETVIZ) \
	$(BE13_API) \
	$(WIFI) \
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
