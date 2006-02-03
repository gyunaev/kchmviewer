messages: rc.cpp
		$(EXTRACTRC) *.rc > rc.cpp
		$(EXTRACTRC) *.ui >> rc.cpp
		$(XGETTEXT) rc.cpp *.h *.cpp -o $(podir)/kchmviewer.pot

SUBDIRS = . pics

bin_PROGRAMS = kchmviewer
kchmviewer_SOURCES = iconstorage.cpp kchmbookmarkwindow.cpp kchmconfig.cpp \
		kchmindexwindow.cpp kchmmainwindow.cpp kchmsearchtoolbar.cpp kchmsearchwindow.cpp \
		kchmsettings.cpp kchmsourcefactory.cpp kchmtextencoding.cpp kchmtreeviewitem.cpp \
		kchmviewwindow.cpp main.cpp xchmfile.cpp kchmdialogchooseurlfromlist.cpp kde-qt.cpp \
		kchmviewwindow_qtextbrowser.cpp kchmviewwindow_khtmlpart.cpp kchmsetupdialog.ui kqtempfile.cpp

# set the include path found by configure
INCLUDES = $(QT_INCLUDES) $(CHM_INCLUDES) $(KDE_INCLUDES)

# the library search path.
kchmviewer_LDADD = $(CHM_LIBS) $(LIB_QT) $(LIB_KDEUI) $(LIB_KHTML)
kchmviewer_LDFLAGS = $(QT_LDFLAGS) $(KDE_LDFLAGS)

METASOURCES = AUTO
KDE_OPTIONS = qtonly
KDE_ICON = AUTO
noinst_HEADERS = bitfiddle.h kchmsettings.h forwarddeclarations.h \
		kchmsourcefactory.h iconstorage.h kchmtextencoding.h kchmbookmarkwindow.h kchmconfig.h \
		kchmtreeviewitem.h kchmdialogchooseurlfromlist.h kchmviewwindow.h kchmindexwindow.h \
		kchmviewwindow_khtmlpart.h kchmmainwindow.h kchmviewwindow_qtextbrowser.h kchmsearchtoolbar.h \
		kde-qt.h kchmsearchwindow.h xchmfile.h kqtempfile.h kqrunprocess.h \
		filetype_handler.h
