#!/bin/sh
# Hopefully you checked out with:
# $ git clone --recursive https://github.com/simsong/tcpflow.git

if [ ! -e src/be13_api/.git ] ;
then
  echo bringing in submodules
  echo You can avoid this step by checking out with git clone --recursive
  git submodule init
  git submodule update
fi
/bin/rm -rf aclocal.m4
autoheader -f
aclocal -I m4
autoconf -f
automake --add-missing --copy
./configure
