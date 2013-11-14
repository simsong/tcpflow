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
## The new way:
# have automake do an initial population iff necessary
if [ ! -e config.guess -o ! -e config.sub -o ! -e install-sh -o ! -e missing ]; then
    /bin/rm -rf aclocal.m4
    autoheader -f
    aclocal -I m4
    autoconf -f
    automake --add-missing --copy
else
    autoreconf -f
fi
echo be sure to run ./configure
## The old way:

# /bin/rm -rf aclocal.m4
# autoheader -f
# aclocal -I m4
# autoconf -f
# automake --add-missing --copy
# ./configure
