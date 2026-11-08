#!/bin/sh
#
# test -L: console output with a named semaphore
#

. $srcdir/test-subs.sh

LOCK=/tcpflow-test-$$

$TCPFLOW -c -r $DMPDIR/test1.pcap > semlock-plain.out 2>/dev/null
if ! $TCPFLOW -c -L $LOCK -r $DMPDIR/test1.pcap > semlock.out 2>semlock.err ; then
  echo "failure: tcpflow -L failed"
  cat semlock.err
  exit 1
fi
if ! cmp -s semlock-plain.out semlock.out ; then
  echo "failure: the output differs with -L"
  exit 1
fi

rm -f semlock-plain.out semlock.out semlock.err /dev/shm/sem$LOCK
exit 0
