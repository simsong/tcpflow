#!/bin/sh
#
# test DLT_NULL captures made on another platform (macOS loopback with IPv6)
#

. $srcdir/test-subs.sh

rm -rf out-null
cmd "$TCPFLOW -o out-null -r $DMPDIR/local.pcap"
if [ ! -f "out-null/::1.00022-::1.50266" ] ; then
  echo "failure: IPv6 flows of a macOS loopback capture were not decoded"
  ls out-null
  exit 1
fi

rm -rf out-null
exit 0
