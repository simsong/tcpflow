#!/bin/sh

# Hopefully you checked out with git clone --recursive git@github.com:simsong/tcpflow.git

if [ ! -d src/be13_api ] ;
then
  echo bringing in submodules
  echo next time check out with git clone --recursive
  git submodule init
  git submodule update
fi
aclocal
autoreconf
automake --add-missing
