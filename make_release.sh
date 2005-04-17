#!/bin/sh

if [ -z "$1" ]; then
	echo "Release version?"
	exit 1;
fi

make distclean
(cd chmlib-0.35 && make distclean)
tar zcf ../kchmviewer-$1.tar.gz .

