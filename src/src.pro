INCLUDEPATH += ../lib/libchmfile

HEADERS += config.h dbus_interface.h dialog_chooseurlfromlist.h dialog_setup.h kde-qt.h keyeventfilter.h \
	mainwindow.h recentfiles.h settings.h tab_bookmarks.h tab_contents.h tab_index.h tab_search.h \
	treeviewitem.h version.h viewwindow.h viewwindowmgr.h viewwindow_qtextbrowser.h viewwindow_qtwebkit.h
	
SOURCES += config.cpp dbus_interface.cpp dialog_chooseurlfromlist.cpp dialog_setup.cpp kde-qt.cpp \
	keyeventfilter.cpp main.cpp mainwindow.cpp recentfiles.cpp settings.cpp tab_bookmarks.cpp \
	tab_contents.cpp tab_index.cpp tab_search.cpp treeviewitem.cpp viewwindow.cpp viewwindowmgr.cpp \
	viewwindow_qtextbrowser.cpp viewwindow_qtwebkit.cpp

TARGETDEPS += ../lib/libchmfile/libchmfile.a 
LIBS +=       ../lib/libchmfile/libchmfile.a -lchm
TARGET = ../bin/kchmviewer
CONFIG += release \
         ordered \
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
window_browser.ui
RESOURCES += resources/images.qrc
QT += webkit dbus network

win32-mingw-g++: {
	QT -= dbus
	HEADERS -= kchmdbusiface.h
	SOURCES -= kchmdbusiface.cpp
	CONFIG -= dbus
}
