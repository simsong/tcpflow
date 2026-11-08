#
# About the tests:
#
# test1.sh - 
# test2.sh - 
# test3.sh - 
#
# About the test files:
#

SH_TESTS = test-index-rewrite.sh test1.sh \
    test-pdfs.sh \
    test-multifile.sh \
    test-iptree.sh \
    test-chroot.sh \
    test-template-escape.sh \
    test-findx.sh

EXTRA_DIST = $(SH_TESTS) test-index-rewrite.py test-subs.sh \
	airsnort-linux-browser_page_load.pcap \
	bug2.pcap \
	bug3.pcap \
	bug4.pcap \
	bug5.pcap \
	bug6.pcap \
	bug7.pcap \
	bug8.pcap \
	flow_test.pcap \
	local.pcap \
	local2.pcap \
	simson.pcap \
	test-gzip.pcap \
	test1-80-50955.pcap \
	test1-one-packet.pcap \
	test1-out-of-order.pcap \
	test1-part1.pcap \
	test1-part2.pcap \
	test1.pcap \
	test2.pcap \
	test3.pcap \
	test4.pcap \
	test5-lines-randomized.pcap \
	test5-lines-randomized2.pcap \
	test5-lines.pcap \
	test7-three-flows.pcap \
	udp.pcap

TESTS = $(SH_TESTS)

CLEANFILES = *.pdf \
	out/010.000.000.001.09999-010.000.000.002.36559--42 \
	out/010.000.000.002.36559-010.000.000.001.09999--42 \
	out/074.125.019.101.00080-192.168.001.102.50956 \
	out/074.125.019.104.00080-192.168.001.102.50955 \
	out/192.168.001.102.50955-074.125.019.104.00080 \
	out/192.168.001.102.50956-074.125.019.101.00080 \
	out/2001:6f8:102d::2d0:9ff:fee3:e8de.59201-2001:6f8:900:7c0::2.00080 \
	out/2001:6f8:900:7c0::2.00080-2001:6f8:102d::2d0:9ff:fee3:e8de.59201 \
	out/report.xml 

nitroba.pcap:
	wget http://downloads.digitalcorpora.org/corpora/packets/2008-nitroba/nitroba.pcap

clean:
	@echo Erase any left over trace files
	/bin/rm -f *.[0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].*

