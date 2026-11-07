#!/bin/sh
#
# test -w with a pcapng input
#

[ -f $DMPDIR/test1-out-of-order.pcap ] || { echo "no pcapng capture"; exit 77; }

. $srcdir/test-subs.sh

OUT=out-unk-pcapng

rm -rf $OUT
cmd "$TCPFLOW -o $OUT -w $OUT/unk.pcap -r $DMPDIR/test1-out-of-order.pcap"

# every packet is TCP, so only the 24-byte pcap header is written
if [ `wc -c < $OUT/unk.pcap` -ne 24 ] ; then
  echo "failure: wrong size of $OUT/unk.pcap"
  exit 1
fi

rm -rf $OUT
exit 0
