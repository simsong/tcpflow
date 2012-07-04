#!/bin/sh
#/bin/rm -rf aclocal.m4
aclocal
autoreconf
automake --add-missing
