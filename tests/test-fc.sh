#!/bin/sh
#
# test -Fc (append the connection counter to all file names)
#

. $srcdir/test-subs.sh

# flow_test.pcap has three connections with the same addresses and ports
DMPFILE=$DMPDIR/flow_test.pcap

rm -rf out-fc
cmd "$TCPFLOW -Fc -o out-fc -r $DMPFILE"

for c in 0 1 2 ; do
  f=out-fc/172.016.005.002.05678-172.016.005.092.09999c$c
  if [ ! -f $f ] ; then
    echo "failure: $f was not created"
    ls out-fc
    exit 1
  fi
done

rm -rf out-fc
exit 0
