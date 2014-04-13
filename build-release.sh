#!/bin/sh

# Export the source code
BUILD_RPM64=1
BUILD_RPM32=1
BUILD_WINDOWS=1

PACKAGE=kchmviewer
BINARYFILE="bin/kchmviewer"

FILE_VERSION="src/version.h"
RPM_OUTDIR="/home/tim/rpmbuild/RPMS"

# Get current version
VERSION_MAJOR=`sed -n 's/^\#define\s\+APP_VERSION_MAJOR\s\+\([0-9a-z]\+\)/\1/p' $FILE_VERSION`
VERSION_MINOR=`sed -n 's/^\#define\s\+APP_VERSION_MINOR\s\+\"\?\([0-9a-z]\+\)\"\?/\1/p' $FILE_VERSION`
CURRENTVER="$VERSION_MAJOR.$VERSION_MINOR"

BUILDDIR="$PACKAGE-$CURRENTVER"
RELEASEDIR="release-$CURRENTVER"

if [ -d "$BUILDDIR" ]; then
	rm -rf "$BUILDDIR"
fi

if [ -d "$RELEASEDIR" ]; then
	rm -rf "$RELEASEDIR"
fi
mkdir "$RELEASEDIR" || exit 1

svn export . "$BUILDDIR/" || exit 1

# Source package
tar zcf "$RELEASEDIR/$PACKAGE-$CURRENTVER.tar.gz" $BUILDDIR || exit 1

# Build 64-bit onr
if [ "$BUILD_RPM64" == 1 ]; then

	# Making the RPM root
	rm -rf "$BUILDDIR/buildroot"
	mkdir -p "$BUILDDIR/buildroot/usr/bin"
	mkdir -p "$BUILDDIR/buildroot/usr/share/applications"
	mkdir -p "$BUILDDIR/buildroot/usr/share/pixmaps"
	cp packages/*.desktop "$BUILDDIR/buildroot/usr/share/applications"
	cp packages/*.png "$BUILDDIR/buildroot/usr/share/pixmaps"

	# Build a 64-bit version 
	(cd "$BUILDDIR" && qmake -r -spec linux-g++-64 "CONGIF+=release" && make -j4) || exit 1
	strip --strip-all "$BUILDDIR/bin/kchmviewer" -o "$BUILDDIR/buildroot/usr/bin/kchmviewer" || exit 1

	# Prepare a spec file
	sed "s/^Version: [0-9.]\\+/Version: $CURRENTVER/" packages/rpm.spec > $BUILDDIR/rpm.spec

	# Build a 64-bit RPM
	rpmbuild -bb --target=x86_64 --buildroot `pwd`"/$BUILDDIR/buildroot/" $BUILDDIR/rpm.spec || exit 1
	mv $RPM_OUTDIR/x86_64/*.rpm "$RELEASEDIR/" || exit 1
fi

# Build 32-bit RPM
if [ "$BUILD_RPM32" == 1 ]; then

	# Clean up first
	pushd "$BUILDDIR"
	make distclean

	# Link the libraries so the linker finds the 32-bit libs instead of 64-bit ones
	for lib in chm pthread QtDBus QtXml QtGui QtCore QtNetwork QtWebKit; do

		libpath=`find /lib /usr/lib/ -name lib$lib\* | sort -r | head -n1`
		if [ -z "$libpath" ]; then
			echo "No library $lib found"
			exit
		fi
	
		ln -s $libpath "src/lib$lib.so"
	done
	popd

	# Making the RPM root
	rm -rf "$BUILDDIR/buildroot"
	mkdir -p "$BUILDDIR/buildroot/usr/bin"
	mkdir -p "$BUILDDIR/buildroot/usr/share/applications"
	mkdir -p "$BUILDDIR/buildroot/usr/share/pixmaps"
	cp packages/*.desktop "$BUILDDIR/buildroot/usr/share/applications"
	cp packages/*.png "$BUILDDIR/buildroot/usr/share/pixmaps"
	
	# Build a 32-bit version 
	(cd "$BUILDDIR" && qmake -r -spec linux-g++-32 && make -j4) || exit 1
	strip --strip-all "$BUILDDIR/bin/kchmviewer" -o "$BUILDDIR/buildroot/usr/bin/kchmviewer" || exit 1

	# Prepare a spec file
	sed "s/^Version: [0-9.]\\+/Version: $CURRENTVER/" packages/rpm.spec > $BUILDDIR/rpm.spec

	# Build a 32-bit RPM
	rpmbuild -bb --target=i586 --buildroot `pwd`"/$BUILDDIR/buildroot/" $BUILDDIR/rpm.spec || exit 1
	mv $RPM_OUTDIR/i586/*.rpm "$RELEASEDIR/" || exit 1
fi

# win32
if [ "$BUILD_WINDOWS" == 1 ]; then
	sh build-win32-mingw.sh || exit 1
	(cd nsis && sh create_installer.sh) || exit 1
	mv nsis/InstallKchmviewer*.exe $RELEASEDIR
fi

rm -rf "$BUILDDIR"
rm -rf "build.win32"
echo "Done! Version $CURRENTVER released!"
