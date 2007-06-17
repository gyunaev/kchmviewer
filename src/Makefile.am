if AMC_USE_KDE
LIB_KDEEXTRADIR = kde
LIB_KDEEXTRA = kde/libkdeextra.a
endif

bin_PROGRAMS = kchmviewer
kchmviewer_SOURCES = iconstorage.cpp kchmbookmarkwindow.cpp kchmconfig.cpp \
			kchmindexwindow.cpp kchmmainwindow.cpp kchmsearchtoolbar.cpp kchmsearchwindow.cpp \
			kchmsettings.cpp kchmsourcefactory.cpp kchmtreeviewitem.cpp kchmviewwindow.cpp main.cpp \
			kchmdialogchooseurlfromlist.cpp kde-qt.cpp kchmviewwindow_qtextbrowser.cpp \
			kchmsetupdialog.ui kqtempfile.cpp kchmnavtoolbar.cpp kchmviewwindowmgr.cpp \
			kchmkeyeventfilter.cpp kchmcontentswindow.cpp kchmsearchengine_impl.cpp \
			kchmsearchengine.cpp

# set the include path found by configure
INCLUDES = $(QT_INCLUDES) $(CHM_INCLUDES) $(KDE_INCLUDES) $(LIBCHMFILE_INCLUDES)

SUBDIRS = $(LIB_KDEEXTRADIR) . pics

# the library search path.
kchmviewer_LDADD = $(top_builddir)/lib/libchmfile/libchmfile.a  $(LIB_KDEEXTRA) \
	$(CHM_LIBS) $(LIB_QT) $(LIB_KDEUI) $(LIB_KHTML)
kchmviewer_LDFLAGS = $(QT_LDFLAGS) $(KDE_LDFLAGS) -L../lib/chmlib/

METASOURCES = AUTO
KDE_OPTIONS = qtonly
KDE_ICON = AUTO
noinst_HEADERS = kchmsettings.h forwarddeclarations.h kchmsourcefactory.h \
			iconstorage.h kchmbookmarkwindow.h kchmconfig.h kchmtreeviewitem.h \
			kchmdialogchooseurlfromlist.h kchmviewwindow.h kchmindexwindow.h \
			kchmmainwindow.h kchmviewwindow_qtextbrowser.h kchmsearchtoolbar.h kde-qt.h \
			kchmsearchwindow.h kqtempfile.h kqrunprocess.h kchmnavtoolbar.h kchmviewwindowmgr.h \
			kchmkeyeventfilter.h kchmcontentswindow.h kchmlistitemtooltip.h kchmsearchengine_impl.h \
			kchmsearchengine.h

messages: rc.cpp
		$(EXTRACTRC) *.rc > rc.cpp
		$(EXTRACTRC) *.ui >> rc.cpp
		$(XGETTEXT) rc.cpp *.h *.cpp -o $(podir)/kchmviewer.pot
