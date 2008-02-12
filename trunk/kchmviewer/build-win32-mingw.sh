#!/bin/sh

# Path to (cross-platform) mingw compiler
MINGWPATH=/home/tim/bin/mingw/bin

BUILDDIR="build.win32"

##################################

if [ -d "$BUILDDIR" ]; then
	rm -rf "$BUILDDIR"
fi

svn export . "$BUILDDIR/" || exit 1
cd "$BUILDDIR"

# Compile it
export PATH=$MINGWPATH:$PATH
qmake -r -spec win32-mingwnt-g++ && make || exit 1

