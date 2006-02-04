#!/bin/sh

DIRS="kde qt kde-intchm qt-intchm"

rm -rf $DIRS || exit 1;

for target in $DIRS; do

	# KDE/qt
	case $target in
	qt*)
		TEXTDESCR_OPTS="Qt only"
		TEST_KDE=0
		CONFIGURE_OPTS=""
	;;

	kde*)
		TEXTDESCR_OPTS="KDE"
		TEST_KDE=1
		CONFIGURE_OPTS="--with-kde"
	;;
	esac

	# int/system chmlib
	case $target in
	-int*)
		TEST_INTCHM=1
		TEXTDESCR_OPTS="$TEXTDESCR_OPTS, with internal libchm"
		CONFIGURE_OPTS="$CONFIGURE_OPTS --with-builtin-chmlib"
	;;

	*)
		TEXTDESCR_OPTS="$TEXTDESCR_OPTS, with system libchm"
		TEST_INTCHM=0
	;;
	esac

	echo "******************************************************************************************"
	echo "Building target in $target: $TEXTDESCR_OPTS"
	echo
	(mkdir $target && cd $target && ../../configure $CONFIGURE_OPTS && make)

	if test "$?" != 0; then
		echo "Failed to build $TEXTDESCR_OPTS in $target"
		exit 1
	fi
 
	# Run some tests
	executable="src/kchmviewer"
	echo -n "Testing the $target build ... "

	# Should it be linked with KDE libs?
	kde_libs=`ldd "$target/$executable" |grep libkde`
	if test "$TEST_KDE" = 1; then
		if test -z "$kde_libs"; then
			echo "Bad build - not linked with KDE libs!"
			exit 1;
		fi
	else
		if test -n "$kde_libs"; then
			echo "Bad build - linked with KDE libs, but should not!"
			exit 1;
		fi
	fi

	# Should it be linked with libchm?
	chm_lib=`ldd "$target/$executable" |grep libchm`
	if test "$TEST_INTCHM" = 1; then
		if test -n "$chm_lib"; then
			echo "Bad build - linked with system-wide libchm instead of internal!"
			exit 1;
		fi
	else
		if test -z "$chm_lib"; then
			echo "Bad build - linked with internal libchm instead of system-wide!"
			exit 1;
		fi
	fi

	# Should KIO slave be build?
	if test "$TEST_KDE" = 1; then
		if test ! -f "$target/kio-msits/kio_msits.la"; then
			echo "Bad build - KIO slave is not built!"
			exit 1;
		fi
	else
		if test -f "$target/kio-msits/kio_msits.la"; then
			echo "Bad build - KIO slave is built, but should not be!"
			exit 1;
		fi
	fi

	echo "OK"
done

exit 0
