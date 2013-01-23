#!/bin/sh
# Hopefully you checked out with git clone --recursive git@github.com:simsong/tcpflow.git

if [ ! -f src/be13_api/.git ] ;
then
  echo bringing in submodules
  echo next time check out with git clone --recursive
  git submodule init
  git submodule update
fi
/bin/rm -rf aclocal.m4
autoheader -f
aclocal -I m4
autoconf -f
automake --add-missing --copy

