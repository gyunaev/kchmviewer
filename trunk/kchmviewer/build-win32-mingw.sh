#!/bin/sh

# Path to (cross-platform) mingw compiler
#MINGWPATH=/home/tim/bin/mingw/bin
#QTPATH=/home/tim/bin/qt-4.6.0/qt/
MINGWPATH=/usr/toolchains/windows-x86-mingw/bin
QMAKE=i686-pc-mingw32-qmake

BUILDDIR="build.win32"

##################################

if [ -d "$BUILDDIR" ]; then
	rm -rf "$BUILDDIR"
fi

svn export . "$BUILDDIR/" || exit 1
cd "$BUILDDIR"

# Compile it
export PATH=$MINGWPATH:$PATH
#$QMAKE -r -spec win32-g++ && make -j4  || exit 1
$QMAKE -r -spec win32-g++ && make || exit 1
