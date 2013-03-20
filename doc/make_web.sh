#!/bin/bash
#
# Create the files for the tcpflow website
DEST=/var/www/digitalcorpora/tcpflow/demo
TCPFLOW=../src/tcpflow
TMP=/tmp/out$$

if [ ! -d $DEST ]; then mkdir -p $DEST ; fi

if [ ! -x $TCPFLOW ]; then (cd .. ; make ) ; fi

run()
{
  DPDF=$DEST/$2
  DPNG=${DPDF%pdf}png
  echo DPDF=$DPDF
  echo DPNG=$DPNG
  $TCPFLOW -o $TMP -x tcpdemux -E netviz -r $1  
  if [ ! -r $TMP/report.pdf ]; then
    echo tcpflow failed
    exit 1
  fi
  mv $TMP/report.pdf $DPDF
  /bin/rm -rf $TMP
  convert -scale 300 $DPDF $DPNG
  ls -l $DPDF $DPNG
}

run /corp/nps/packets/2008-nitroba/nitroba.pcap nitroba.pdf

