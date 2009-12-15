#!/bin/sh

# Export the source code

PACKAGE=kchmviewer
BINARYFILE="bin/kchmviewer"

FILE_VERSION="src/version.h"
RPM_ARCH="i586"
RPM_OUTDIR="/usr/src/packages/RPMS/$RPM_ARCH"

# Get current version
VERSION_MAJOR=`sed -n 's/^\#define\s\+APP_VERSION_MAJOR\s\+\([0-9]\+\)/\1/p' $FILE_VERSION`
VERSION_MINOR=`sed -n 's/^\#define\s\+APP_VERSION_MINOR\s\+\([0-9]\+\)/\1/p' $FILE_VERSION`
CURRENTVER="$VERSION_MAJOR.$VERSION_MINOR"

BUILDDIR="build-$CURRENTVER"
RELEASEDIR="release-$CURRENTVER"

if [ -d "$BUILDDIR" ]; then
	rm -rf "$BUILDDIR"
fi

if [ -d "$RELEASEDIR" ]; then
	rm -rf "$RELEASEDIR"
fi
mkdir "$RELEASEDIR" || exit 1

svn export . "$BUILDDIR/" || exit 1

# Source package without examples
tar zcf "$RELEASEDIR/$PACKAGE-$CURRENTVER.tar.gz" $BUILDDIR || exit 1

# Build it 
(cd "$BUILDDIR" && qmake && make -j4) || exit 1

# Making an RPM
rm -rf "$BUILDDIR/buildroot"
mkdir -p "$BUILDDIR/buildroot/usr/bin"
mkdir -p "$BUILDDIR/buildroot/usr/share/applications"
mkdir -p "$BUILDDIR/buildroot/usr/share/pixmaps"
strip --strip-all "$BUILDDIR/$BINARYFILE"
cp "$BUILDDIR/$BINARYFILE" "$BUILDDIR/buildroot/usr/bin/" || exit 1
cp packages/*.desktop "$BUILDDIR/buildroot/usr/share/applications"
cp packages/*.png "$BUILDDIR/buildroot/usr/share/pixmaps"

# Prepare a spec file
sed "s/^Version: [0-9.]\\+/Version: $CURRENTVER/" packages/rpm.spec > $BUILDDIR/rpm.spec

rpmbuild -bb --target=$RPM_ARCH --buildroot `pwd`"/$BUILDDIR/buildroot/" $BUILDDIR/rpm.spec || exit 1
mv $RPM_OUTDIR/*.rpm $RELEASEDIR || exit 1
rm -rf "$BUILDDIR"

# win32
sh build-win32-mingw.sh || exit 1
(cd nsis && sh create_installer.sh) || exit 1
mv nsis/InstallKchmviewer*.exe $RELEASEDIR

rm -rf "$BUILDDIR"
rm -rf "build.win32"
echo "Done! Version $CURRENTVER released!"
