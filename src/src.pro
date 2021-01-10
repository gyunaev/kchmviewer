
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
    textencodings.h \
    treeitem_toc.h \
    treeitem_index.h

SOURCES += \
    config.cpp \
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
    viewwindowmgr.cpp \
    navigationpanel.cpp \
    checknewversion.cpp \
    toolbarmanager.cpp \
    toolbareditor.cpp \
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

# General per-platform settings
macx:{
    HEADERS += kchmviewerapp.h
    SOURCES += kchmviewerapp.cpp
    QMAKE_INFO_PLIST=resources/Info.plist
    QMAKE_POST_LINK += cp resources/*.icns ${DESTDIR}/kchmviewer.app/Contents/Resources;
    LIBS += ../lib/libebook/libebook.a
    POST_TARGETDEPS += ../lib/libebook/libebook.a
}

win32:{
    CONFIG( debug, debug|release ) {
            LIBS += "../lib/libebook/debug/ebook.lib"
    } else {
            LIBS += "../lib/libebook/release/ebook.lib"
    }

    LIBS += -lwsock32 -loleaut32
}

unix:!macx: {
    QT += dbus
    HEADERS += dbus_interface.h
    SOURCES += dbus_interface.cpp
    CONFIG += dbus
    LIBS += ../lib/libebook/libebook.a
}

greaterThan(QT_MAJOR_VERSION, 4) {
    # Qt 5
    greaterThan(QT_MINOR_VERSION, 5) {
        # Qt 5.6+
        error("You use Qt5.6+ - QWebEngine is not yet suitable for kchmviewer and is not supported")
        QT += webengine webenginewidgets
        DEFINES += USE_WEBENGINE
        SOURCES += viewwindow_webengine.cpp dataprovider_qwebengine.cpp
        HEADERS += dataprovider_qwebengine.h viewwindow_webengine.h
    } else {
        # Qt 5.0-5.5
        QT += webkit webkitwidgets
        DEFINES += USE_WEBKIT
        SOURCES += viewwindow_webkit.cpp dataprovider_qwebkit.cpp
        HEADERS += dataprovider_qwebkit.h viewwindow_webkit.h
    }
} else {
    message("Qt4 is not supported anymore, please do not report any errors")
    QT += webkit webkitwidgets
    DEFINES += USE_WEBKIT
    SOURCES += viewwindow_webkit.cpp dataprovider_qwebkit.cpp
    HEADERS += dataprovider_qwebkit.h viewwindow_webkit.h
}
