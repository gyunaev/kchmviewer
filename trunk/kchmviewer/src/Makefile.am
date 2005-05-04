bin_PROGRAMS = kchmviewer
kchmviewer_SOURCES = froglogic_getopt.cpp iconstorage.cpp \
		kchmbookmarkwindow.cpp kchmconfig.cpp kchmindexwindow.cpp kchmmainwindow.cpp \
		kchmsearchtoolbar.cpp kchmsearchwindow.cpp kchmsettings.cpp kchmsourcefactory.cpp \
		kchmtextencoding.cpp kchmtreeviewitem.cpp kchmviewwindow.cpp main.cpp xchmfile.cpp \
		kchmdialogchooseurlfromlist.cpp kde-qt.cpp kchmviewwindow_qtextbrowser.cpp \
		kchmviewwindow_khtmlpart.cpp

# set the include path found by configure
INCLUDES = $(QT_INCLUDES) -I$(CHM_INCLUDES) $(KDE_INCLUDES)

# the library search path.
kchmviewer_LDFLAGS = $(QT_LDFLAGS) $(LIB_QT) $(KDE_LDFLAGS) $(LIB_KDEUI) $(LIB_KHTML)

#LIB_KDEPRINT = -lkdeprint
#LIB_KDEUI = -lkdeui
#LIB_KFILE = -lkio
#LIB_KHTML = -lkhtml

METASOURCES = AUTO
KDE_OPTIONS = qtonly
noinst_HEADERS = kchmdialogchooseurlfromlist.h kchmviewwindow_qtextbrowser.h \
	kchmviewwindow_khtmlpart.h
