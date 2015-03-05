#!/bin/sh
aclocal
autoheader
autoconf
automake --add-missing --copy
#./configure
#make
#make check
#make install
