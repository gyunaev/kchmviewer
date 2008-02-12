#!/bin/sh

# File to get the version from
FILE_VERSION=../src/version.h

# Generated binary
BINARY=../build.win32/bin/kchmviewer.exe

# Qt libs
QTLIBS=/mnt/disk_c/Qt/4.3.2/bin/

# Start the mojo
ln -s $BINARY kchmviewer.exe
ln -s $QTLIBS/QtGui4.dll QtGui4.dll  
ln -s $QTLIBS/QtCore4.dll QtCore4.dll

export NSISDIR=/home/tim/bin/nsis

# Get current, and save the next version
VERSION=`sed -n 's/^\#define\s\+APP_VERSION\s\+\"\([0-9.a-zA-Z]\+\)\"/\1/p' $FILE_VERSION`

INSTNAME="InstallKchmviewer-$VERSION.exe"
echo "Creating $INSTNAME"

makensis installer.nsis 

# Remove unused
rm kchmviewer.exe
rm QtGui4.dll  
rm QtCore4.dll

mv InstallKchmViewer.exe $INSTNAME
