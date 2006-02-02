#!/bin/sh

CHMDIR="/home/tim/Distro/Ebooks/"
KCHMVIEWER="../src/kchmviewer"

find $CHMDIR -iname "*.chm" -print -exec $KCHMVIEWER --shortautotestmode {} \; 2>&1 | tee autotest.log

