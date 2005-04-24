#!/bin/sh

if [ -z "$1" ]; then
	echo "Release version?"
	exit 1;
fi

./configure && make distclean && make -f Makefile.cvs && tar zcf ../kchmviewer-$1.tar.gz ../kchmviewer

