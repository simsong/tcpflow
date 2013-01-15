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
	be13_api/unicode_escape.cpp 

NETVIZ = \
	netviz/plot.cpp \
	netviz/plot.h \
	netviz/time_histogram.cpp \
	netviz/time_histogram.h \
	netviz/address_histogram.cpp \
	netviz/address_histogram.h \
	netviz/port_histogram.cpp \
	netviz/port_histogram.h \
	netviz/packetfall.cpp \
	netviz/packetfall.h \
	netviz/one_page_report.cpp \
	netviz/one_page_report.h

tcpflow_SOURCES = datalink.cpp flow.cpp \
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
	$(NETVIZ) \
	$(BE13_API) \
	http-parser/http_parser.c \
	http-parser/http_parser.h \
	mime_map.cpp

EXTRA_DIST =\
	http-parser/AUTHORS \
	http-parser/CONTRIBUTIONS \
	http-parser/LICENSE-MIT \
	http-parser/Makefile \
	http-parser/README.md \
	http-parser/http_parser.gyp 

testiph: tcpflow
	echo Testing the IP histogram
	/bin/rm -rf iptest out.txt
	./tcpflow -o iptest -S iphtest=1 -r /corp/nps/packets/2008-nitroba/nitroba.pcap >out.txt
	diff ../tests/iphtest1-results.txt out.txt 
	echo iptree appears okay.
