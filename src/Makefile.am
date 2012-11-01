# Programs that we compile:
bin_PROGRAMS = tcpflow

AM_CPPFLAGS = -I${top_srcdir}/src/be13_api

# bulk_extractor 1.3 API:

BE13_API = be13_api/bulk_extractor_i.h
	be13_api/cppmutex.h \
	be13_api/feature_recorder.h \
	be13_api/feature_recorder_set.h \
	be13_api/md5.h \
	be13_api/sbuf.h \
	be13_api/sbuf_flex_scanner.h \
	be13_api/sbuf_private.h \
	be13_api/sbuf_stream.h \
	be13_api/utf8.h \
	be13_api/utf8/checked.h \
	be13_api/utf8/core.h \
	be13_api/utf8/unchecked.h \
	be13_api/xml.h 

tcpflow_SOURCES = datalink.cpp flow.cpp \
	pcap_fake.h pcap_fake.cpp \
	main.cpp \
	plugin.cpp\
	sbuf.cpp\
	feature_recorder.cpp feature_recorder_set.cpp \
	tcpip.cpp tcpdemux.h tcpdemux.cpp tcpflow.h xml.h xml.cpp util.cpp \
	unicode_escape.h unicode_escape.cpp \
	md5.h md5.c iface_pcb.cpp iface_pcb.h pcb_timehistogram.cpp \
	$(BE13_API)

