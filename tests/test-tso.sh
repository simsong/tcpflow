#!/bin/sh
#
# test packets with ip_len 0, as captured on the sending host with TCP segmentation offload
#

. $srcdir/test-subs.sh

# bug7.pcap: the second of three packets has ip_len 0
DMPFILE=$DMPDIR/bug7.pcap

rm -rf out-tso
cmd "$TCPFLOW -o out-tso -r $DMPFILE"

checkmd5 out-tso/"192.168.020.054.64261-192.168.020.056.20008" "194cb76e5a64f16a82042caf2d93a638" "3108"

rm -rf out-tso
exit 0
