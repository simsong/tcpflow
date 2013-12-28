#!/bin/sh
#

. $srcdir/test-subs.sh

# create PDFs for all of the pcap files
for i in *.pcap
do
  echo $i
  cmd "$TCPFLOW -Fg -e netviz -o tmp$$ -r $i"
  cmd "mv tmp$$/report.pdf `basename $i .pcap`.pdf"
  echo ""
  /bin/rm -rf tmp$$
done
