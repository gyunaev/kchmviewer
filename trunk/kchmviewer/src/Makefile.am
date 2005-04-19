bin_PROGRAMS = kchmviewer
kchmviewer_SOURCES = froglogic_getopt.cpp iconstorage.cpp \
	kchmbookmarkwindow.cpp kchmconfig.cpp kchmindexwindow.cpp kchmmainwindow.cpp \
	kchmsearchtoolbar.cpp kchmsearchwindow.cpp kchmsettings.cpp kchmsourcefactory.cpp \
	kchmtextencoding.cpp kchmtreeviewitem.cpp kchmviewwindow.cpp main.cpp xchmfile.cpp

# set the include path found by configure
INCLUDES = $(QT_INCLUDES) -I$(top_srcdir)/$(CHM_INCLUDES) $(KDE_INCLUDES)
# $(all_includes)

# the library search path.
kchmviewer_LDFLAGS = $(QT_LIBS) $(KDE_LIBS)
#$(all_libraries)

METASOURCES = AUTO
KDE_OPTIONS = qtonly nofinal
