#!/bin/bash
# Hopefully you checked out with:
# $ git clone --recursive https://github.com/simsong/tcpflow.git

## The new way:
# have automake do an initial population if necessary
if [ ! -e config.guess -o ! -e config.sub -o ! -e install-sh -o ! -e missing -o ! -e test-driver ]; then
    autoheader -f
    touch NEWS README AUTHORS ChangeLog
    touch stamp-h
    aclocal -I m4
    autoconf -f
    automake --add-missing --copy
else
    autoreconf -f
fi

# bootstrap is complete
echo
echo The bootstrap.sh is complete.  Be sure to run ./configure.
echo
