. ./test-subs.sh

NITROBA=/corp/nps/packets/2008-nitroba/nitroba.pcap
if [ -r $NITROBA ]; then
  /bin/rm -rf out1
  cmd "$TCPFLOW -S netviz_max_histogram_size=1000 -S netviz_histogram_dump=1 -o out1 -r $NITROBA"
else
  echo $NITROBA not present.
fi
exit 0

