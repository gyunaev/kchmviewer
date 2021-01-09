
TEMPLATE = app
TARGET = ../bin/kchmviewer
CONFIG *= c++11 warn_on threads # xml dbus precompile_header
QT += \
    webkit \
    dbus \
    xml \
    network \
    widgets \
    webkitwidgets \
    printsupport

HEADERS += \
    config.h \
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

SOURCES += \
    config.cpp \
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

INCLUDEPATH *= ../lib/libebook ../lib/libchm

LIBS += \
    -L"../lib/libebook" -lebook \
    -L"../lib/libchm" -lchm \
    -lzip

linux-g++*:{
    LIBS += -lX11
}

# This is used by cross-build on 64-bit when building a 32-bit version
linux-g++-32: {
       LIBS += -L.
}

win32-g++*: {
    QT -= dbus
    HEADERS -= dbus_interface.h
    SOURCES -= dbus_interface.cpp
###    CONFIG -= dbus
###    LIBS -= ../lib/libebook/libebook.a
###    POST_TARGETDEPS -= ../lib/libebook/libebook.a

###    CONFIG( debug, debug|release ) {
###            LIBS += "../lib/libebook/debug/libebook.a"
###    } else {
###            LIBS += "../lib/libebook/release/libebook.a"
###    }

    LIBS += -lwsock32 -lz -loleaut32
}

macx-g++: {
    HEADERS -= dbus_interface.h
    SOURCES -= dbus_interface.cpp
###    CONFIG -= dbus
    HEADERS += kchmviewerapp.h
    SOURCES += kchmviewerapp.cpp
    QMAKE_INFO_PLIST=resources/Info.plist
    QMAKE_POST_LINK += cp resources/*.icns ${DESTDIR}/kchmviewer.app/Contents/Resources;
}
