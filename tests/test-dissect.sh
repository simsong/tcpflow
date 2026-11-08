#!/bin/sh
#
# test -K (per flow pcap output) with a TCP segment shorter than the TCP header
#

. $srcdir/test-subs.sh

# truncated-tcp.pcap: a 2-byte TCP segment, then a SYN 10.0.0.1:40000 -> 10.0.0.2:80
DMPFILE=$DMPDIR/truncated-tcp.pcap

rm -rf out-dissect
cmd "$TCPFLOW -K -o out-dissect -r $DMPFILE"

flows=`ls out-dissect | grep '\.pcap$'`
if [ x"$flows" != x"010.000.000.001.40000-010.000.000.002.00080.pcap" ] ; then
  echo "failure: expected only the 40000->80 flow, got:"
  echo "$flows"
  exit 1
fi

rm -rf out-dissect
exit 0
