#
# About the tests:
#
# test1.sh - 
# test2.sh - 
# test3.sh - 
#
# About the test files:
#

SH_TESTS = test1.sh test-pdfs.sh test-multifile.sh test-iptree.sh

EXTRA_DIST = $(SH_TESTS) test-subs.sh test1.pcap test2.pcap test3.pcap test4.pcap  

TESTS = $(SH_TESTS)

CLEANFILES = \
	out/010.000.000.001.09999-010.000.000.002.36559--42 \
	out/010.000.000.002.36559-010.000.000.001.09999--42 \
	out/074.125.019.101.00080-192.168.001.102.50956 \
	out/074.125.019.104.00080-192.168.001.102.50955 \
	out/192.168.001.102.50955-074.125.019.104.00080 \
	out/192.168.001.102.50956-074.125.019.101.00080 \
	out/2001:6f8:102d::2d0:9ff:fee3:e8de.59201-2001:6f8:900:7c0::2.00080 \
	out/2001:6f8:900:7c0::2.00080-2001:6f8:102d::2d0:9ff:fee3:e8de.59201 \
	out/report.xml 

clean:
	@echo Erase any left over trace files
	/bin/rm -f *.[0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].*

