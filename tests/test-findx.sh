#!/bin/sh
#
# test -I: index offsets follow the data when it is shifted, and the index is sorted
#

[ -f $DMPDIR/test1-out-of-order.pcap ] || { echo "no pcapng capture"; exit 77; }

. $srcdir/test-subs.sh

rm -rf out-findx
cmd "$TCPFLOW -I -o out-findx -r $DMPDIR/test1-out-of-order.pcap"
got=`cat out-findx/074.125.019.104.00080-192.168.001.102.50955.findx`
expected="0|1223315694.695990|1396
1418|1223315694.711975|65"
if [ x"$got" != x"$expected" ] ; then
  echo "failure: wrong index:"
  echo "$got"
  exit 1
fi

rm -rf out-findx
exit 0
