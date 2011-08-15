#!/bin/sh

aclocal
libtoolize --copy --force
aclocal
autoconf
autoheader
automake --add-missing --copy
