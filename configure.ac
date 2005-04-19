dnl Process this file with autoconf to produce a configure script.
dnl Most of this file was shamelessly stolen from Licq Qt plugin, which has similar configuration options
AC_INIT(src/main.cpp)
AC_CONFIG_AUX_DIR(admin)
AC_CANONICAL_SYSTEM
AC_ARG_PROGRAM

dnl All versioning is done via the following line
AM_CONFIG_HEADER(src/config.h)
AM_INIT_AUTOMAKE(KchmViewer, 0.1)

dnl Chuck #defines for PACKAGE and VERSION into config.h
AC_DEFINE_UNQUOTED(APP_NAME, "$PACKAGE", [ Application name ] )
AC_DEFINE_UNQUOTED(APP_VERSION, "$VERSION", [ Application version as text ])
AC_DEFINE_UNQUOTED(APP_INT_VERSION,$INT_VERSION, [ Application version as integer ])
prefix="/usr/local"

AC_PROG_CXX

dnl Check for X and extra X libs needed
AC_PATH_XTRA
if test "$no_x" = yes; then
  AC_MSG_ERROR(You need to have the X11 libraries and headers installed)
fi

dnl Check for QT & KDE
AC_PATH_QT
AC_PATH_QT_INC

if test "$have_qt_inc" = "no"; then
  AC_MSG_ERROR([

I can't find the QT header files.

Install the QT development package, or if you have them installed, override
this check with the --with-qt-includes argument, and I'll take your word for
it.
])

fi

AC_PATH_KDE
AC_PATH_KDE_INCLUDES

AC_PATH_QT_LIB

if test "$have_qt_lib" = "no"; then
  AC_MSG_ERROR([

I can't find the QT libraries. It is recommended to set the QTDIR environment
variable.

Install the QT libraries, or if you have them installed, override this check
with the --with-qt-libraries argument, and I'll take your word for it.
])

fi

dnl Check for QT version
AC_CHECK_QT_SETUP

AC_PATH_QT_MOC
AC_PATH_QT_FINDTR
AC_PATH_QT_MSGTOQM
AC_PATH_QT_MERGETR

AC_PATH_KDE_LIBRARIES

CHMLIBDIR="chmlib-0.35"
CHM_INCLUDES="$CHMLIBDIR/src"
CHM_LIBS="\$(top_srcdir)/$CHMLIBDIR/src/libchm.a"

dnl configure chmlib, if not already configured
if test ! -f "$chm_libs"; then
	if test ! -f "$CHMLIBDIR/Makefile"; then
		echo
		echo "Configuring chmlib ..."
		(cd "$CHMLIBDIR" && CC="$CC" CXX="$CXX" sh configure --host=$host --build=$build)
	fi
	CHMLIB_SUBDIR="\$(top_srcdir)/$CHMLIBDIR"
fi

LIBS="$LIBS $CHM_LIBS"
AC_SUBST(CHMLIB_SUBDIR)
AC_SUBST(CHM_INCLUDES)

AC_OUTPUT(src/Makefile Makefile)

echo ""
echo "Please remember to use GNU make, often installed as gmake."
echo ""
echo "Install prefix : $prefix"
if test "$have_kde" = yes; then
  echo "KDE support    : includes in $kde_includes, libs in $kde_libraries"
else
  echo "KDE support    : disabled."
fi
echo "Qt includes    : $ac_cv_header_qtinc"
echo "Qt libraries   : $ac_qt_libdir, $ac_qt_libname"
echo "Qt moc         : $MOC"
echo ""
