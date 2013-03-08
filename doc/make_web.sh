#!/bin/bash
#
# Create the files for the tcpflow website
DEST=/var/www/digitalcorpora/tcpflow/demo
TCPFLOW=../src/tcpflow

if [ ! -d $DEST ]; then mkdir -s $DEST ; fi

if [ ! -x $TCPFLOW ]; then (cd .. ; make ) ; fi

