#!/bin/sh
#
# test that -K writes Ethernet captures with the Ethernet link type (1)
#

. $srcdir/test-subs.sh

rm -rf out-k
cmd "$TCPFLOW -K -o out-k -r $DMPDIR/test1.pcap"
found=0
for f in out-k/*.pcap ; do
  [ -f "$f" ] || continue
  found=1
  linktype=`od -An -t u4 -j 20 -N 4 "$f" | tr -cd '0-9'`
  linktype=`expr "$linktype" + 0`   # OpenBSD od pads with zeros
  echo "$f: link type $linktype"
  if [ x"$linktype" != x"1" ] ; then
    echo "failure: $f has link type $linktype, expected 1 (Ethernet)"
    exit 1
  fi
done
if [ $found = 0 ] ; then
  echo "failure: -K wrote no pcap files in out-k"
  ls -la out-k
  exit 1
fi

rm -rf out-k
exit 0
