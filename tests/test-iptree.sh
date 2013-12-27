. ./test-subs.sh

cmd "$TCPFLOW -S netviz_max_histogram_size=1000 -S netviz_histogram_dump=1 -o out1 -r /corp/nps/packets/2008-nitroba/nitroba.pcap"
/bin/rm -rf out1
