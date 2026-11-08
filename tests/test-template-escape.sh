#!/bin/sh
#
# test that a literal "%%c" in -T does not count as the connection counter
#

. $srcdir/test-subs.sh

OUT=out-template-escape

rm -rf $OUT
# all four flows expand to the same name; without a counter this never ends
$TCPFLOW -o $OUT -T 'x%%c' -r $DMPDIR/test1.pcap &
pid=$!
waited=0
while kill -0 $pid 2>/dev/null ; do
  if [ $waited -ge 30 ] ; then
    kill -9 $pid
    echo "failure: tcpflow -T 'x%%c' did not finish"
    exit 1
  fi
  sleep 1
  waited=`expr $waited + 1`
done
if ! wait $pid ; then
  echo "failure: tcpflow -T 'x%%c' failed"
  exit 1
fi
if [ ! -f "$OUT/x%c" ] || [ ! -f "$OUT/x%cc1" ] ; then
  echo "failure: the counter was not appended"
  ls $OUT
  exit 1
fi

rm -rf $OUT
exit 0
