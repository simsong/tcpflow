# Programs that we compile:
bin_PROGRAMS = tcpflow

# bulk_extractor 1.3 API:

BE13_API = bulk_extractor_i.h cppmutex.h feature_recorder.h feature_recorder_set.h md5.h sbuf.h sbuf_flex_scanner.h sbuf_private.h sbuf_stream.h utf8.h utf8/checked.h utf8/core.h utf8/unchecked.h xml.h 

tcpflow_SOURCES = datalink.cpp flow.cpp \
	pcap_fake.h pcap_fake.cpp \
	main.cpp \
	tcpip.cpp tcpdemux.h tcpdemux.cpp tcpflow.h xml.h xml.cpp util.cpp \
	md5.h md5.c iface_pcb.cpp iface_pcb.h pcb_timehistogram.cpp \
	$(BE13_API)

