#!/bin/sh

CHMDIR="/home/tim/ebooks"
KCHMVIEWER="src/kchmviewer"

find $CHMDIR -iname "*.chm" -print -exec $KCHMVIEWER --autotestmode {} \; 2>&1 | tee autotest.log
echo "Computer is about to shut down!!!" | sudo wall 
sleep 60
sudo poweroff

