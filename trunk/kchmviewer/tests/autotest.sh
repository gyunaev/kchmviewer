#!/bin/sh

CHMDIR="/home/tim/Distro/Ebooks/ /mnt/disk_d/Docs"
#KCHMVIEWER="../src/kchmviewer"
KCHMVIEWER="../build/src/kchmviewer"
COMMONLOG="autotest.log"
FATALLOG="fatal.log"
CMDOPTIONS="--nocrashhandler"

#find $CHMDIR -iname "*.chm" -print -exec 

find $CHMDIR -iname "*.chm" -print | while read file; do

echo "Testing file $file"
echo "File $file" >> $COMMONLOG
$KCHMVIEWER $CMDOPTIONS --shortautotestmode "$file" >>$COMMONLOG 2>&1

if test $? != 0; then
	echo "$file FAILED, exit code $?!" >> FATALLOG
fi

done
