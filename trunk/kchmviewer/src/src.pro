INCLUDEPATH += ../lib/libchmfile

HEADERS += kchmsettings.h kchmbookmarkwindow.h kchmconfig.h kchmtreeviewitem.h \
			kchmdialogchooseurlfromlist.h kchmviewwindow.h kchmindexwindow.h \
			kchmmainwindow.h kchmviewwindow_qtextbrowser.h kde-qt.h \
			kchmsearchwindow.h kqtempfile.h kqrunprocess.h kchmviewwindowmgr.h \
			kchmkeyeventfilter.h kchmcontentswindow.h kchmsearchengine_impl.h \
			kchmsearchengine.h \
			kchmsetupdialog.h
SOURCES += kchmbookmarkwindow.cpp kchmconfig.cpp \
			kchmindexwindow.cpp kchmmainwindow.cpp kchmsearchwindow.cpp \
			kchmsettings.cpp kchmtreeviewitem.cpp kchmviewwindow.cpp main.cpp \
			kchmdialogchooseurlfromlist.cpp kde-qt.cpp kchmviewwindow_qtextbrowser.cpp \
			kqtempfile.cpp kchmviewwindowmgr.cpp \
			kchmkeyeventfilter.cpp kchmcontentswindow.cpp kchmsearchengine_impl.cpp \
			kchmsearchengine.cpp \
			kchmsetupdialog.cpp
TARGETDEPS += ../lib/libchmfile/libchmfile.a 
LIBS +=       ../lib/libchmfile/libchmfile.a -lchm
TARGET = ../bin/kchmviewer
CONFIG += debug \
		 warn_on \
		 qt \
		 precompile_header
TEMPLATE = app
QT +=  qt3support
FORMS += tab_bookmarks.ui \
tab_index.ui \
tab_contents.ui \
tab_search.ui \
dialog_setup.ui \
dialog_topicselector.ui \
window_main.ui \
window_browser.ui
RESOURCES += resources/images.qrc
