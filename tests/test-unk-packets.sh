#!/bin/sh
#
# test -w with one and with several -r files
#

. $srcdir/test-subs.sh

DMPFILE=$DMPDIR/udp.pcap
OUT=out-unk

rm -rf $OUT
cmd "$TCPFLOW -o $OUT -w $OUT/one.pcap -r $DMPFILE"
cmd "$TCPFLOW -o $OUT -w $OUT/two.pcap -r $DMPFILE -r $DMPFILE"

# udp.pcap has no TCP, so every packet goes to -w; the 24-byte pcap header is written once
one=`wc -c < $OUT/one.pcap`
two=`wc -c < $OUT/two.pcap`
if [ $two -ne `expr 2 \* $one - 24` ] ; then
  echo "failure: -w with two -r files wrote $two bytes, expected `expr 2 \* $one - 24`"
  exit 1
fi

rm -rf $OUT
exit 0
