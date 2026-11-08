#!/bin/sh
#
# test that report.xml has MAC addresses only for Ethernet captures
#

. $srcdir/test-subs.sh

rm -rf out-mac
# local.pcap is a DLT_NULL (loopback) capture
cmd "$TCPFLOW -o out-mac -r $DMPDIR/local.pcap"
if grep -q "mac_daddr\|mac_saddr" out-mac/report.xml ; then
  echo "failure: report.xml has MAC addresses for a loopback capture"
  grep -o "mac_[sd]addr='[^']*'" out-mac/report.xml | sort -u
  exit 1
fi

rm -rf out-mac
cmd "$TCPFLOW -o out-mac -r $DMPDIR/test1.pcap"
if ! grep -q "mac_daddr='00:1f:5b:c7:fa:d2'" out-mac/report.xml ; then
  echo "failure: report.xml lost the MAC addresses of an Ethernet capture"
  exit 1
fi

rm -rf out-mac
exit 0
