## -*- mode: m4 -*-
dnl Copyright (c) 1998 N. D. Bellamy
dnl Copyright (c) 2000 Dirk A. Mueller

AC_DEFUN([AC_PATH_QT],
[
  AC_ARG_WITH(qt,
    [  --with-qt               where QT v3.x or higher is located. ],
    [  QTDIR="$withval" ])
])

AC_DEFUN([AC_PATH_QT_LIB],
[
  AC_REQUIRE_CPP()
  AC_REQUIRE([AC_PATH_X])
  AC_MSG_CHECKING(for QT libraries)

  AC_ARG_WITH(qt-libraries,
    [  --with-qt-libraries     where the QT libraries are located. ],
    [  ac_qt_libraries="$withval" ], ac_qt_libraries="")

  AC_CACHE_VAL(ac_cv_lib_qtlib, [

      qt_libname=
      qt_libdir=

      dnl No they didnt, so lets look for them...
      dnl If you need to add extra directories to check, add them here.
      if test -z "$ac_qt_libraries"; then
        qt_library_dirs="\
          /usr/lib/qt3/lib \
          /usr/lib/qt2/lib \
          /usr/lib \
          /usr/local/lib \
          /usr/lib/qt \
          /usr/lib/qt/lib \
          /usr/local/lib/qt \
          /usr/local/qt/lib \
          /usr/X11/lib \
          /usr/X11/lib/qt \
          /usr/X11R6/lib \
          /usr/X11R6/lib/qt"
      else
        qt_library_dirs="$ac_qt_libraries"
      fi

      if test -n "$QTDIR"; then
        qt_library_dirs="$QTDIR/lib $qt_library_dirs"
      fi

      if test -n "$QTLIB"; then
        qt_library_dirs="$QTLIB $qt_library_dirs"
      fi

      for qt_dir in $qt_library_dirs; do
        if test -z $ac_kde || test "$ac_kde" = "no" || test "$kde_version" -ge 3; then
          if test -r "$qt_dir/libqt-mt.so"; then
            ac_qt_libname=-lqt-mt
            ac_qt_libdir=$qt_dir
            break
          else
            echo "tried $qt_dir/libqt-mt.so" >&AC_FD_CC 
          fi

          if test -r "$qt_dir/libqt-mt.so.3"; then
            ac_qt_libname=-lqt-mt
            ac_qt_libdir=$qt_dir
            break
          else
            echo "tried $qt_dir/libqt-mt.so.3" >&AC_FD_CC
          fi
        fi

        # If no KDE or KDE < 3 we might try for libqt, too
        if test "$ac_kde" = "no" || test "$kde_version" -lt 3; then
          if test -r "$qt_dir/libqt.so"; then
            ac_qt_libname=-lqt
            ac_qt_libdir=$qt_dir
            break
          else
            echo "tried $qt_dir/libqt.so" >&AC_FD_CC 
          fi
        fi
      done

    ac_cv_lib_qtlib="ac_qt_libname=$ac_qt_libname ac_qt_libdir=$ac_qt_libdir"
  ])

  eval "$ac_cv_lib_qtlib"

  dnl Define a shell variable for later checks

  if test -z "$ac_qt_libdir"; then
    have_qt_lib="no"
    AC_MSG_RESULT([no :-(])
  else
    have_qt_lib="yes"
    AC_MSG_RESULT([yes, lib: $ac_qt_libname in $ac_qt_libdir])
  fi

  QT_LDFLAGS="-L$ac_qt_libdir"
  QT_LIBDIR="$ac_qt_libdir"
  LIB_QT="$ac_qt_libname"
  AC_SUBST(QT_LDFLAGS)
  AC_SUBST(QT_LIBDIR)
  AC_SUBST(LIB_QT)
])

AC_DEFUN([AC_PATH_QT_INC],
[
  AC_REQUIRE_CPP()
  AC_REQUIRE([AC_PATH_X])
  AC_MSG_CHECKING(for QT includes)

  AC_ARG_WITH(qt-includes,
    [  --with-qt-includes      where the QT headers are located. ],
    [  ac_qt_includes="$withval" ], ac_qt_includes="")

  AC_CACHE_VAL(ac_cv_header_qtinc, [

    dnl Did the user give --with-qt-includes?
    if test -z "$ac_qt_includes"; then

      dnl No they didn't, so lets look for them...
      dnl If you need to add extra directories to check, add them here.
      qt_include_dirs="\
        /usr/lib/qt3/include \
        /usr/lib/qt2/include \
        /usr/lib/qt/include \
        /usr/include/qt \
        /usr/include/qt3 \
        /usr/local/qt/include \
        /usr/local/include/qt \
        /usr/X11/include/qt \
        /usr/X11/include/X11/qt \
        /usr/X11R6/include \
        /usr/X11R6/include/qt \
        /usr/X11R6/include/X11/qt \
        /usr/X11/lib/qt/include"

      if test -n "$QTDIR"; then
        qt_include_dirs="$QTDIR/include $qt_include_dirs"
      fi

      if test -n "$QTINC"; then
        qt_include_dirs="$QTINC $qt_include_dirs"
      fi

      for qt_dir in $qt_include_dirs; do
        if test -r "$qt_dir/qbig5codec.h"; then
          if test -r "$qt_dir/qtranslatordialog.h"; then
            AC_MSG_ERROR([
              This is not Qt 3.x or later. Somebody cheated you.

              Most likely this is because you've installed a crappy
              outdated Redhat 6.2 RPM. Go to ftp://people.redhat.com/bero/qt
              and update to the correct one.
            ])
          else
            ac_qt_includes=$qt_dir
          fi
          break
        fi
      done
    fi

    ac_cv_header_qtinc=$ac_qt_includes

  ])

  if test -z "$ac_cv_header_qtinc"; then
    have_qt_inc="no"
  else
    have_qt_inc="yes"
  fi
  
  AC_MSG_RESULT([$ac_cv_header_qtinc])
  QT_INCLUDES="-I$ac_cv_header_qtinc"
  QT_INCDIR="$ac_cv_header_qtinc"
  AC_SUBST(QT_INCLUDES)
  AC_SUBST(QT_INCDIR)
])


AC_DEFUN([AC_PATH_QT_MOC],
[
  AC_ARG_WITH(qt-moc,
    [  --with-qt-moc           where the QT 3.x moc is located. ],
    [  ac_qt_moc="$withval" ], ac_qt_moc="")

  if test -z "$ac_qt_moc"; then
    dnl search on our own

    if test -z "$QTDIR"; then
      AC_MSG_WARN(environment variable QTDIR is not set, moc might not be found)
    fi

    AC_PATH_PROG(
      MOC,
      moc,
      $QTDIR/bin/moc,
      $QTDIR/bin:/usr/lib/qt2/bin:/usr/bin:/usr/X11R6/bin:/usr/lib/qt/bin:/usr/local/qt/bin:$PATH
    )
  else
    AC_MSG_CHECKING(for moc)

    if test -f $ac_qt_moc && test -x $ac_qt_moc; then
      MOC=$ac_qt_moc
    else
      AC_MSG_ERROR(
        --with-qt-moc expects path and name of the moc
      )
    fi

    AC_MSG_RESULT($MOC)
  fi

  if test -z "$MOC"; then
    AC_MSG_ERROR(couldn't find Qt moc. Please use --with-qt-moc)
  fi

  dnl Check if we have the right moc
  if ! fgrep QCString "$MOC" > /dev/null; then
    AC_MSG_ERROR([

        The Qt meta object compiler (moc)
        $MOC
        found by configure is not the one part of Qt 3.x.

        It's likely that the found one is the one shipped with
        Qt 1.x or Qt 2.x. That one will not work.

        Please check your installation.
        Use the --with-qt-moc option to specify the path and name
        of the moc compiler shipped with your Qt 3.x lib.
        Some distributions rename it to "moc2", maybe you find that
        on your system.

        see ./configure --help for details.
    ])
  fi

  AC_SUBST(MOC)
])

AC_DEFUN([AC_CHECK_QT_SETUP],
[
  AC_MSG_CHECKING(for QT >= 3.x)

  AC_CACHE_VAL(ac_cv_qt_setup, 
  [
    AC_LANG_SAVE
    AC_LANG_CPLUSPLUS
    
    save_CXXFLAGS="$CXXFLAGS"
    save_LDFLAGS="$LDFLAGS"
    save_LIBS="$LIBS"
     
    CXXFLAGS="$CXXFLAGS $QT_INCLUDES $X_CFLAGS"
    LDFLAGS="$X_LIBS $QT_LDFLAGS $LDFLAGS"
    LIBS="$LIB_QT $X_PRE_LIBS -lX11 -lXext $LIBS"

    AC_TRY_LINK([
      #include <qglobal.h>
    ],
    [
      #if QT_VERSION < 334 
         choke me
      #endif
    ],
      ac_cv_qt_334=yes,
      ac_cv_qt_334=no
    )

    AC_TRY_LINK([
      #include <qglobal.h>
    ],
    [
      #if QT_VERSION < 300 
         choke me
      #endif
    ],
      ac_cv_qt_setup=yes,
      ac_cv_qt_setup=no
    )
   ])

  AC_MSG_RESULT($ac_cv_qt_setup)

  if test "$ac_cv_qt_setup" != "yes"; then
    AC_MSG_ERROR([
      Sorry, but you need QT version 3.x or higher to compile the Qt gui plugin.
    ])
  fi

  dnl One more check for Qt 3.3.4
  AC_MSG_CHECKING(whether QT version is 3.3.4 and above)
  AC_MSG_RESULT($ac_cv_qt_334)

  if test "$ac_cv_qt_334" != "yes"; then
    AC_MSG_WARN([
      Your QT version is less than 3.3.4. Increase/decrease font commands will not work correctly with your version of Qt. You are recommended to upgrade QT.
    ])
  fi
])

AC_DEFUN([AC_PATH_QT_FINDTR],
[
  AC_PATH_PROG(
    QT_FINDTR,
    findtr,
    echo,
    $QTDIR/bin:/usr/bin:/usr/X11R6/bin:/usr/lib/qt/bin:/usr/local/qt/bin:$PATH)

  if test "$QT_FINDTR" = "echo"; then
    echo "** findtr could not be found. You're losing the localisation."
  fi

  AC_SUBST(QT_FINDTR)
])

AC_DEFUN([AC_PATH_QT_MSGTOQM],
[
  AC_PATH_PROG(
    QT_MSG2QM,
    msg2qm,
    echo,
    $QTDIR/bin:/usr/bin:/usr/X11R6/bin:/usr/lib/qt/bin:/usr/local/qt/bin:$PATH)

  if test "$QT_MSG2QM" = "echo"; then
    echo "** msg2qm could not be found. You're losing the localisation."
  fi

  AC_SUBST(QT_MSG2QM)
])

AC_DEFUN([AC_PATH_QT_MERGETR],
[
  AC_PATH_PROG(
    QT_MERGETR,
    mergetr,
    echo,
    $QTDIR/bin:/usr/bin:/usr/X11R6/bin:/usr/lib/qt/bin:/usr/local/qt/bin:$PATH)

  if test "$QT_MERGETR" = "echo"; then
    echo "** mergetr could not be found. You're losing the localisation."
  fi

  AC_SUBST(QT_MERGETR)
])

## ------------------------------------------------------------------------
## KDE detection. Terribly simple.
## ------------------------------------------------------------------------

AC_DEFUN([LICQ_FIND_FILE],
[
$3=""
for i in $2;
do
  for j in $1;
  do
    if test -r "$i/$j"; then
      $3=$i
      break 2
    fi
  done
done
])

AC_DEFUN([AC_PATH_KDE],
[
  AC_ARG_WITH(kde,
    [  --with-kde              compile with KDE support. ],
    [  ac_kde="$withval" ])

  kde_version=2
])

AC_DEFUN([AC_PATH_KDE_INCLUDES],
[
  AC_REQUIRE([AC_PATH_QT_INC])

  AC_MSG_CHECKING([for KDE includes])

  ac_kde_includes=""
  kde_includes=""

  dnl check for KDE includes
  kde_incdirs="/opt/kde3/include /opt/kde2/include /opt/kde/include /usr/lib/kde/include /usr/local/kde/include /usr/kde/include /usr/include/kde /usr/include /usr/local/include $x_includes $qt_includes"
  if test -n "$KDEDIR"; then
    kde_incdirs="$KDEDIR/include $KDEDIR $kde_incdirs"
  fi

  LICQ_FIND_FILE(kaction.h, $kde_incdirs, kde_incdir)
  kde_includes=$kde_incdir

  if test "$ac_kde" != "no" && test -n "$kde_includes" && test -n "$ac_kde"; then
    if test "$kde_includes" != "$x_includes" && test "$kde_includes" != "$qt_includes"; then
      KDE_INCLUDES="-I$kde_includes"
    fi

    AC_MSG_RESULT([$kde_includes])

    # KDE 2 or 3?
    if test -r $kde_includes/kdeversion.h; then
	  # KDE 3 or later ;-)
      kde_version=`grep -w '#define KDE_VERSION_MAJOR' < $kde_includes/kdeversion.h | tr -d '#A-Za-z_\t '`
	else
	  # KDE 2
	  kde_version=`grep -w '#define KDE_VERSION_MAJOR' < $kde_includes/kapp.h | tr -d '#A-Za-z_\t '`
	fi

  else
    AC_MSG_RESULT([no])
	kde_includes=""
    KDE_INCLUDES=""
  fi

  AC_SUBST(KDE_INCLUDES)
  AC_SUBST(kde_includes)
])

AC_DEFUN([AC_PATH_KDE_LIBRARIES],
[
  AC_REQUIRE([AC_PATH_QT_LIB])
  AC_REQUIRE([AC_PATH_QT_INC])
  AC_REQUIRE([AC_PATH_KDE_INCLUDES])

  AC_MSG_CHECKING([for KDE libraries])

  ac_kde_libraries=""
  kde_libraries=""

  dnl check for KDE libraries
  kde_libdirs="/opt/kde3/lib /opt/kde2/lib /opt/kde/lib /usr/lib/kde/lib /usr/local/kde/lib /usr/kde/lib /usr/lib/kde /usr/lib /usr/local/lib /usr/X11R6/lib /usr/X11R6/kde/lib"
  if test -n "$KDEDIR"; then
    kde_libdirs="$KDEDIR/lib $KDEDIR $kde_libdirs"
  fi

  LICQ_FIND_FILE(libkdecore.la, $kde_libdirs, kde_libdir)
  kde_libraries=$kde_libdir

  if test "$ac_kde" != "no" && test -n "$kde_includes" && test -n "$kde_libraries" && test -n "$ac_kde"; then
    if test "$kde_libraries" != "$x_libraries" && test "$kde_libraries" != "$qt_libraries"; then
      KDE_LDFLAGS="-L$kde_libraries"
    fi

    AC_MSG_RESULT([$kde_libraries])
    AC_DEFINE(USE_KDE, 1, [use KDE support])
    LIB_NAME="licq_kde-gui.la"

    # KDE 2 or 3? (libkfile no longer exists in KDE3, so link with -lkio)
    if test -f $kde_libraries/libkfile.so ; then
      KDE_LIBS="-lkfile"
    else
      KDE_LIBS="-lkio"
    fi
    AC_SUBST(KDE_LIBS)

    have_kde=yes
    AC_SUBST(have_kde)
  else
    LIB_NAME="licq_qt-gui.la"
    AC_MSG_RESULT([no])
    KDE_LDFLAGS=""
    KDE_LIBS=""
  fi

  AC_SUBST(LIB_NAME)
  AC_SUBST(KDE_LDFLAGS)
  AC_SUBST(kde_libraries)
])

dnl Like AC_CHECK_HEADER, but it uses the already-computed -I directories.
AC_DEFUN([AC_CHECK_X_HEADER], [
  ac_save_CPPFLAGS="$CPPFLAGS"
  if test \! -z "$includedir" ; then
    CPPFLAGS="$CPPFLAGS -I$includedir"
  fi
  CPPFLAGS="$CPPFLAGS $X_CFLAGS"
  AC_CHECK_HEADER([$1],[$2],[$3], [#include <X11/Xlib.h>])
  CPPFLAGS="$ac_save_CPPFLAGS"
])

dnl Like AC_CHECK_LIB, but it used the -L dirs set up by the X checks.

AC_DEFUN([AC_CHECK_X_LIB], [
  ac_save_CPPFLAGS="$CPPFLAGS"
  ac_save_LDFLAGS="$LDFLAGS"

  if test \! -z "$includedir" ; then
    CPPFLAGS="$CPPFLAGS -I$includedir"
  fi

  dnl note: $X_CFLAGS includes $x_includes
  CPPFLAGS="$CPPFLAGS $X_CFLAGS"

  if test \! -z "$libdir" ; then
    LDFLAGS="$LDFLAGS -L$libdir"
  fi

  dnl note: $X_LIBS includes $x_libraries

  LDFLAGS="$LDFLAGS $X_LIBS"
  AC_CHECK_LIB([$1], [$2], [$3], [$4], [$5])
  CPPFLAGS="$ac_save_CPPFLAGS"
  LDFLAGS="$ac_save_LDFLAGS"]
)

dnl check if a given compiler flag works
AC_DEFUN([KDE_CHECK_COMPILER_FLAG],
[
AC_MSG_CHECKING(whether $CXX supports -$1)
kde_cache=`echo $1 | sed 'y%.=/+-%___p_%'`
AC_CACHE_VAL(ac_cv_prog_cxx_$kde_cache,
[
echo 'void f(){}' >conftest.cc
if test -z "`$CXX -$1 -c conftest.cc 2>&1`"; then
  eval "ac_cv_prog_cxx_$kde_cache=yes"
else
  eval "ac_cv_prog_cxx_$kde_cache=no"
fi
rm -f conftest*
])
if eval "test \"`echo '$ac_cv_prog_cxx_'$kde_cache`\" = yes"; then
 AC_MSG_RESULT(yes)
 :
 $2
else
 AC_MSG_RESULT(no)
 :
 $3
fi
])
