INCLUDEPATH += ../lib/libebook
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
    version.h \
    viewwindow.h \
    viewwindowmgr.h \
    navigationpanel.h \
    checknewversion.h \
    toolbarmanager.h \
    toolbareditor.h \
    qwebviewnetwork.h \
    textencodings.h \
    treeitem_toc.h \
    treeitem_index.h
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
    viewwindow.cpp \
    viewwindowmgr.cpp \
    navigationpanel.cpp \
    checknewversion.cpp \
    toolbarmanager.cpp \
    toolbareditor.cpp \
    qwebviewnetwork.cpp \
    textencodings.cpp \
    treeitem_toc.cpp \
    treeitem_index.cpp
POST_TARGETDEPS += ../lib/libebook/libebook.a
LIBS += ../lib/libebook/libebook.a -lchm -lzip -lX11
TARGET = ../bin/kchmviewer
CONFIG += threads \
    warn_on \
    precompile_header \
    xml \
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
	xml \
    network \
    widgets \
    webkitwidgets \
    printsupport

win32-g++*: {
    QT -= dbus
    HEADERS -= dbus_interface.h
    SOURCES -= dbus_interface.cpp
    CONFIG -= dbus
    LIBS -= -lchm ../lib/libebook/libebook.a
    POST_TARGETDEPS -= ../lib/libebook/libebook.a
    DEFINES += USE_PATCHED_CHMLIB
    
	CONFIG( debug, debug|release ) {
		LIBS += "../lib/libebook/debug/libebook.a"
	} else {
		LIBS += "../lib/libebook/release/libebook.a"
	}    

	LIBS += -lwsock32 ../lib/libebook/chmlib-win32/chmlib.lib -lzip -lz
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
