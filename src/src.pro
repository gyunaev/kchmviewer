INCLUDEPATH += ../lib/libchmfile
HEADERS += config.h \
    dbus_interface.h \
    dialog_chooseurlfromlist.h \
    dialog_setup.h \
    kde-qt.h \
    keyeventfilter.h \
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
    viewwindow_qtextbrowser.h \
    viewwindow_qtwebkit.h \
    navigationpanel.h \
    checknewversion.h \
    toolbarmanager.h \
    toolbareditor.h
SOURCES += config.cpp \
    dbus_interface.cpp \
    dialog_chooseurlfromlist.cpp \
    dialog_setup.cpp \
    kde-qt.cpp \
    keyeventfilter.cpp \
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
    viewwindow_qtextbrowser.cpp \
    viewwindow_qtwebkit.cpp \
    navigationpanel.cpp \
    checknewversion.cpp \
    toolbarmanager.cpp \
    toolbareditor.cpp
TARGETDEPS += ../lib/libchmfile/libchmfile.a
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
win32-g++: {
    QT -= dbus
    HEADERS -= dbus_interface.h
    SOURCES -= dbus_interface.cpp
    CONFIG -= dbus
    LIBS -= -lchm 
    LIBS += -lwsock32 ../lib/libchmfile/chmlib-win32/chmlib.lib
    DEFINES += USE_PATCHED_CHMLIB
}
