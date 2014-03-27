INCLUDEPATH += ../lib/libchmfile
HEADERS += config.h \
    dbus_interface.h \
    dialog_chooseurlfromlist.h \
    dialog_setup.h \
    kde-qt.h \
    mainwindow.h \
    recentfiles.h \
    settings.h \
    tab_bookmarks.h \
    tab_contents.h \
    tab_index.h \
    tab_search.h \
    treeviewitem.h \
    version.h \
    viewwindow.h \
    viewwindowmgr.h \
    navigationpanel.h \
    checknewversion.h \
    toolbarmanager.h \
    toolbareditor.h \
    qwebviewnetwork.h
SOURCES += config.cpp \
    dbus_interface.cpp \
    dialog_chooseurlfromlist.cpp \
    dialog_setup.cpp \
    kde-qt.cpp \
    main.cpp \
    mainwindow.cpp \
    recentfiles.cpp \
    settings.cpp \
    tab_bookmarks.cpp \
    tab_contents.cpp \
    tab_index.cpp \
    tab_search.cpp \
    treeviewitem.cpp \
    viewwindow.cpp \
    viewwindowmgr.cpp \
    navigationpanel.cpp \
    checknewversion.cpp \
    toolbarmanager.cpp \
    toolbareditor.cpp \
    qwebviewnetwork.cpp
POST_TARGETDEPS += ../lib/libchmfile/libchmfile.a
LIBS += ../lib/libchmfile/libchmfile.a -lchm
TARGET = ../bin/kchmviewer
CONFIG += threads \
    warn_on \
    qt \
    precompile_header \
    dbus
TEMPLATE = app
FORMS += tab_bookmarks.ui \
    tab_index.ui \
    tab_contents.ui \
    tab_search.ui \
    dialog_setup.ui \
    dialog_topicselector.ui \
    mainwindow.ui \
    window_browser.ui \
    navigatorpanel.ui \
    dialog_about.ui \
    toolbareditor.ui
RESOURCES += resources/images.qrc
QT += webkit \
    dbus \
    network

win32-g++*: {
    QT -= dbus
    HEADERS -= dbus_interface.h
    SOURCES -= dbus_interface.cpp
    CONFIG -= dbus
    LIBS -= -lchm ../lib/libchmfile/libchmfile.a
    POST_TARGETDEPS -= ../lib/libchmfile/libchmfile.a
    DEFINES += USE_PATCHED_CHMLIB
    
	CONFIG( debug, debug|release ) {
		LIBS += "../lib/libchmfile/debug/libchmfile.a"
	} else {
		LIBS += "../lib/libchmfile/release/libchmfile.a"
	}    

    LIBS += -lwsock32 ../lib/libchmfile/chmlib-win32/chmlib.lib
}

macx-g++: {
    HEADERS -= dbus_interface.h
    SOURCES -= dbus_interface.cpp
    CONFIG -= dbus
    HEADERS += kchmviewerapp.h
    SOURCES += kchmviewerapp.cpp
    QMAKE_INFO_PLIST=resources/Info.plist
    QMAKE_POST_LINK += cp resources/*.icns ${DESTDIR}/kchmviewer.app/Contents/Resources;
}

linux-g++-32: {
	LIBS += -L.
}
