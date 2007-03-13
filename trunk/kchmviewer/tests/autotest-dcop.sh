#!/bin/sh

CHMDIR="/mnt/ebooks /mnt/disk_d/Docs"
KCHMVIEWER="kde/src/kchmviewer"
#KCHMVIEWER="../build/src/kchmviewer"
COMMONLOG="autotest.log"
FATALLOG="fatal.log"
CMDOPTIONS="--nocrashhandler"

find $CHMDIR -iname "*.chm" -print | while read file; do

echo "Testing file $file"
echo "File $file" >> $COMMONLOG
$KCHMVIEWER $CMDOPTIONS "$file" >>$COMMONLOG 2>&1 &
pid=$!
dname="kchmviewer-$pid"

while [ -z `dcop $dname qt interfaces 2>/dev/null | head -n 1` ]; do
	sleep 1;
done

dcop $dname KCHMDCOPIface guiFindInIndex a
if test $? != 0; then
	echo "dcop Index failed" >> FATALLOG
	kill $pid
	continue
fi

res=`dcop $dname KCHMDCOPIface searchQuery this | head -n 1`
if test $? != 0; then
	echo "dcop Search failed" >> FATALLOG
	kill $pid
	continue
fi

if test -z "$res"; then
	echo "dcop search returned empty string" >> FATALLOG
	continue
fi

dcop $dname KCHMDCOPIface guiSearchQuery this
if test $? != 0; then
	echo "dcop guiSearch failed" >> FATALLOG
	kill $pid
	continue
fi

sleep 1
dcop $dname MainApplication-Interface quit

wait $pid

if test $? != 0; then
	echo "$file FAILED, exit code $?!" >> FATALLOG
fi

done
