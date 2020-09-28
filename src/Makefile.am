# Programs that we compile:
bin_PROGRAMS = tcpflow

if WIFI_ENABLED
WIFI_INCS = -I${top_srcdir}/src/wifipcap
else
WIFI_INCS =
endif

AM_CPPFLAGS = -I${top_srcdir}/src/be13_api $(WIFI_INCS)

CONFIG_CLEAN_FILES = config.h		# old location of config.h

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

WIFI = 	datalink_wifi.cpp \
	datalink_wifi.h \
	scan_wifiviz.cpp \
	wifipcap/TimeVal.cpp \
	wifipcap/TimeVal.h \
	wifipcap/arp.h \
	wifipcap/cpack.cpp \
	wifipcap/cpack.h \
	wifipcap/ether.h \
	wifipcap/ethertype.h \
	wifipcap/extract.h \
	wifipcap/icmp.h \
	wifipcap/ieee802_11_radio.h \
	wifipcap/ip.h \
	wifipcap/ip6.h \
	wifipcap/ipproto.h \
	wifipcap/llc.h \
	wifipcap/os.h \
	wifipcap/oui.h \
	wifipcap/prism.h \
	wifipcap/radiotap.h \
	wifipcap/tcp.h \
	wifipcap/types.h \
	wifipcap/udp.h \
	wifipcap/util.h \
	wifipcap/wifipcap.cpp \
	wifipcap/wifipcap.h

if WIFI_ENABLED
WIFI_FILES = $(WIFI)
else
WIFI_FILES =
endif

DFXML_WRITER = be13_api/dfxml/src/dfxml_writer.cpp \
      be13_api/dfxml/src/dfxml_writer.h \
      be13_api/dfxml/src/hash_t.h

DFXML_READER = be13_api/dfxml/src/dfxml_reader.cpp \
      be13_api/dfxml/src/dfxml_reader.h \
      be13_api/dfxml/src/hash_t.h


tcpflow_SOURCES = \
	$(DFXML_WRITER) $(NETVIZ) $(BE13_API) $(WIFI_FILES) \
	datalink.cpp flow.cpp \
	tcpflow.cpp \
	tcpip.h tcpip.cpp \
	tcpdemux.h tcpdemux.cpp \
	intrusive_list.h \
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

# Removed because it hasn't been updated to Python 3:
	scan_python.cpp \


EXTRA_DIST =\
	inet_ntop.c \
	inet_ntop.h \
	http-parser/AUTHORS \
	http-parser/CONTRIBUTIONS \
	http-parser/LICENSE-MIT \
	http-parser/Makefile \
	http-parser/README.md \
	http-parser/http_parser.gyp \
	wifipcap/README.txt \
	wifipcap/TimeVal.cpp \
	wifipcap/TimeVal.h \
	wifipcap/arp.h \
	wifipcap/ether.h \
	wifipcap/ethertype.h \
	wifipcap/extract.h \
	wifipcap/icmp.h \
	wifipcap/ieee802_11_radio.h \
	wifipcap/ip.h \
	wifipcap/ip6.h \
	wifipcap/ipproto.h \
	wifipcap/os.h \
	wifipcap/oui.h \
	wifipcap/prism.h \
	wifipcap/radiotap.h \
	wifipcap/sample.cpp \
	wifipcap/tcp.h \
	wifipcap/types.h \
	wifipcap/udp.h \
	wifipcap/util.cpp \
	wifipcap/util.h \
	wifipcap/wifipcap.cpp \
	wifipcap/wifipcap.h


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
