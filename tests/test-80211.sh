#!/bin/sh
#
# test a DLT_IEEE802_11 capture: test1.pcap as 802.11 data frames
#

. $srcdir/test-subs.sh

OUT=out-80211

rm -rf $OUT $OUT-eth
cmd "$TCPFLOW -o $OUT -r $DMPDIR/wifi-80211.pcap"
cmd "$TCPFLOW -o $OUT-eth -r $DMPDIR/test1.pcap"

if ! diff -r -x report.xml $OUT-eth $OUT ; then
  echo "failure: the 802.11 flows differ from the Ethernet flows"
  exit 1
fi

rm -rf $OUT $OUT-eth
exit 0
