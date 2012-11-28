#!/bin/sh
#/bin/rm -rf aclocal.m4
git submodule init
git submodule update
aclocal
autoreconf
automake --add-missing
