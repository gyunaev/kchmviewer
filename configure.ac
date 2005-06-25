dnl Process this file with autoconf to produce a configure script.
dnl Most of this file was shamelessly stolen from Licq Qt plugin, which has similar configuration options
AC_INIT(src/main.cpp)
AC_CONFIG_AUX_DIR(admin)
AC_CANONICAL_SYSTEM
AC_ARG_PROGRAM

dnl All versioning is done via the following line
AM_CONFIG_HEADER(src/config.h)
AM_INIT_AUTOMAKE(KchmViewer, 0.92)

dnl Chuck #defines for PACKAGE and VERSION into config.h
AC_DEFINE_UNQUOTED(APP_NAME, "$PACKAGE", [ Application name ] )
AC_DEFINE_UNQUOTED(APP_VERSION, "$VERSION", [ Application version as text ])
AC_DEFINE_UNQUOTED(APP_INT_VERSION,$INT_VERSION, [ Application version as integer ])

dnl Checks for programs.
AC_CHECK_COMPILERS

dnl Check for X and extra X libs needed
AC_PATH_XTRA
if test "$no_x" = yes; then
  AC_MSG_ERROR(You need to have the X11 libraries and headers installed)
fi

KDE_PROG_LIBTOOL
AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)
AC_PATH_QT

EXTRA_SUBDIRS=""
CHMLIBDIR="chmlib-0.35"
CHM_INCLUDES="\$(top_srcdir)/$CHMLIBDIR/"
CHM_LIBS="\$(top_builddir)/$CHMLIBDIR/libchm.la"

AC_ARG_WITH(kde,    AC_HELP_STRING([--with-kde],[enable KDE support]))

if test "x$with_kde" = "xyes"; then
	KDE_SET_PREFIX
	AC_PATH_KDE
	AM_KDE_WITH_NLS
	AC_DEFINE(USE_KDE, 1, [use KDE support])
	EXTRA_SUBDIRS="$EXTRA_SUBDIRS kio-msits"
fi

if test "x$with_kde" != "xyes"; then
	include_ARTS_FALSE="yes"
	AC_PREFIX_DEFAULT(${prefix:-/usr/local})
fi

AC_SUBST(EXTRA_SUBDIRS)
AC_SUBST(CHM_INCLUDES)
AC_SUBST(CHM_LIBS)

AC_OUTPUT(src/Makefile Makefile kio-msits/Makefile chmlib-0.35/Makefile)


echo ""
echo "Please remember to use GNU make, often installed as gmake."
echo ""
echo "Install prefix : $prefix"
if test "$have_kde" = yes; then
  echo "KDE support    : includes in $kde_includes, libs in $kde_libraries"
else
  echo "KDE support    : disabled."
fi
echo "Qt includes    : $QT_INCLUDES"
echo "Qt libraries   : $LIB_QT"
echo ""
