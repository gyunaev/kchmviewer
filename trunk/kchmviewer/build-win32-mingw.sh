#!/bin/sh

# Path to (cross-platform) mingw compiler
MINGWPATH=/home/tim/bin/mingw/bin
QTPATH=/home/tim/bin/qt-4.4.0

BUILDDIR="build.win32"

##################################

if [ -d "$BUILDDIR" ]; then
	rm -rf "$BUILDDIR"
fi

svn export . "$BUILDDIR/" || exit 1
cd "$BUILDDIR"

# Compile it
export PATH=$MINGWPATH:$PATH
$QTPATH/bin/qmake -r -spec win32-mingw-g++ && make -j4 || exit 1
