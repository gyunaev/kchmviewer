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


# Source package
svn export . "$BUILDDIR/" || exit 1
tar zcf "$RELEASEDIR/$PACKAGE-$CURRENTVER.tar.gz" $BUILDDIR || exit 1

# win32
#sh build-win32-mingw.sh -nsis || exit 1
#mv build.win32/nsis/InstallKchmviewer*.exe $RELEASEDIR
#rm -rf "build.win32"

# Linux RPMs
for target in qt5-32 qt5-64 qt4-32 qt4-64; do

	echo "Building for $target"
	rm -rf "$BUILDDIR"
	svn export . "$BUILDDIR/" || exit 1

	# Get the Qt version
	case $target in
		qt4-*)
			QMAKE=qmake
			QTLIBS="QtDBus QtXml QtGui QtCore QtNetwork QtWebKit"
			RPMSUFFIX="qt4"
			;;

		qt5-*)
			QMAKE=qmake-qt5
			QTLIBS="Qt5WebKitWidgets Qt5PrintSupport Qt5WebKit Qt5Widgets Qt5Xml Qt5DBus Qt5Network Qt5Gui Qt5Core GL"
			RPMSUFFIX="qt5"
			;;

		*)
			echo "Invalid target"
			exit 1
	esac

	# Get the arch
	case $target in
		*-32)
			QMAKESPEC="linux-g++-32"
			RPMARCH="i586"
			LINKLIBS="pthread chm zip $QTLIBS"

			;;

		*-64)
			QMAKESPEC="linux-g++-64"
			RPMARCH="x86_64"
			;;

		*)
			echo "Invalid arch"
			exit 1
	esac

	# Hack the libs
	if [ -n "$LINKLIBS" ]; then
		pushd $BUILDDIR

		# Link the libraries so the linker finds the 32-bit libs instead of 64-bit ones
		for lib in $LINKLIBS; do

			libpath=`find /lib /usr/lib/ -maxdepth 1 -name lib$lib.so | sort -r | head -n1`
			if [ -z "$libpath" ]; then
				libpath=`find /lib /usr/lib/ -maxdepth 1 -name lib$lib.so\.[0-9] | sort -r | head -n1`

				if [ -z "$libpath" ]; then
					echo "No library $lib found"
					exit
				fi
			fi
	
			ln -s $libpath "src/lib$lib.so"
		done
		popd
	fi

	# Build it	
	(cd "$BUILDDIR" && $QMAKE -r -spec $QMAKESPEC "CONGIF+=release" && make -j4) || exit 1

	# Making the RPM root
	rm -rf "$BUILDDIR/buildroot"
	mkdir -p "$BUILDDIR/buildroot/usr/bin"
	mkdir -p "$BUILDDIR/buildroot/usr/share/applications"
	mkdir -p "$BUILDDIR/buildroot/usr/share/pixmaps"
	cp packages/*.desktop "$BUILDDIR/buildroot/usr/share/applications"
	cp packages/*.png "$BUILDDIR/buildroot/usr/share/pixmaps"
	strip --strip-all "$BUILDDIR/bin/kchmviewer" -o "$BUILDDIR/buildroot/usr/bin/kchmviewer" || exit 1

	# Prepare a spec file
	sed "s/^Version: [0-9.]\\+/Version: $CURRENTVER/" packages/rpm.spec > $BUILDDIR/rpm.spec

	# Build an RPM
	rpmbuild -bb --target=$RPMARCH --buildroot `pwd`"/$BUILDDIR/buildroot/" $BUILDDIR/rpm.spec || exit 1
	mv $RPM_OUTDIR/$RPMARCH/kchmviewer-$CURRENTVER-1.$RPMARCH.rpm "$RELEASEDIR/kchmviewer-$CURRENTVER-1.${RPMARCH}-${RPMSUFFIX}.rpm" || exit 1
	rm -rf "$BUILDDIR"
done

echo "Done! Version $CURRENTVER released!"

