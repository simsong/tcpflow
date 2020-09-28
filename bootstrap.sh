#!/bin/bash
# Hopefully you checked out with:
# $ git clone --recursive https://github.com/simsong/tcpflow.git

# Make sure we have automake installed
function usage() {
  echo tcpflow bootstrap:
  echo be sure to run the appropriate CONFIGURE script to install the necessary packages.
  exit 1
}

automake --help 1>/dev/null 2>&1 || usage

for sub in be13_api http-parser
do
  if [ ! -r src/$sub/.git ] ;
  then
    echo bringing in submodules
    echo next time check out with git clone --recursive
    git submodule init
    git submodule update
  fi
done

## The new way:
# have automake do an initial population iff necessary
if [ ! -e config.guess -o ! -e config.sub -o ! -e install-sh -o ! -e missing -o ! -e test-driver ]; then
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
