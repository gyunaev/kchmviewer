INCLUDEPATH += ../lib/libchmfile

HEADERS += kchmsettings.h kchmbookmarkwindow.h kchmconfig.h kchmtreeviewitem.h \
			kchmdialogchooseurlfromlist.h kchmviewwindow.h kchmindexwindow.h \
			kchmmainwindow.h kchmviewwindow_qtextbrowser.h kde-qt.h \
			kchmsearchwindow.h kchmviewwindowmgr.h \
			kchmkeyeventfilter.h kchmcontentswindow.h kchmsetupdialog.h \
 version.h \
 kchmviewwindow_qtwebkit.h kchmdbusiface.h
SOURCES += kchmbookmarkwindow.cpp kchmconfig.cpp \
			kchmindexwindow.cpp kchmmainwindow.cpp kchmsearchwindow.cpp \
			kchmsettings.cpp kchmtreeviewitem.cpp kchmviewwindow.cpp main.cpp \
			kchmdialogchooseurlfromlist.cpp kde-qt.cpp kchmviewwindow_qtextbrowser.cpp \
			kchmviewwindowmgr.cpp \
			kchmkeyeventfilter.cpp kchmcontentswindow.cpp kchmsetupdialog.cpp \
 kchmviewwindow_qtwebkit.cpp kchmdbusiface.cpp
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
window_main.ui \
window_browser.ui
RESOURCES += resources/images.qrc
QT += webkit dbus network

win32-mingw-g++: {
	QT -= dbus
	HEADERS -= kchmdbusiface.h
	SOURCES -= kchmdbusiface.cpp
	CONFIG -= dbus
}
