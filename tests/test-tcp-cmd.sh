#!/bin/sh
#
# test that tcp_cmd children do not disturb reading the input
#

. $srcdir/test-subs.sh

OUT=out-tcp-cmd

rm -rf $OUT $OUT-plain
cmd "$TCPFLOW -o $OUT-plain -r $DMPDIR/tcp-cmd.pcap"
if ! $TCPFLOW -o $OUT -S tcp_cmd=true -r $DMPDIR/tcp-cmd.pcap 2>tcp-cmd.err ; then
  echo "failure: tcpflow with tcp_cmd failed"
  cat tcp-cmd.err
  exit 1
fi
if grep -q invalid tcp-cmd.err ; then
  echo "failure: the input was corrupted"
  cat tcp-cmd.err
  exit 1
fi
if ! diff -r -x report.xml $OUT-plain $OUT ; then
  echo "failure: the flows differ with tcp_cmd"
  exit 1
fi

rm -rf $OUT $OUT-plain tcp-cmd.err
exit 0
