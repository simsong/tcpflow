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
	$(NETVIZ) \
	net_tcp.cpp \
	$(BE13_API) \
	http-parser/http_parser.c \
	mime_map.cpp

