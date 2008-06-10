INCLUDE_DIRECTORIES( ${CMAKE_BINARY_DIR}/src )

# Project files
SET( kchmviewerSources 
	kchmbookmarkwindow.cpp 
	kchmconfig.cpp 
	kchmindexwindow.cpp 
	kchmmainwindow.cpp 
	kchmsearchwindow.cpp 
	kchmsettings.cpp 
	kchmtreeviewitem.cpp 
	kchmviewwindow.cpp
	main.cpp 
	kchmdialogchooseurlfromlist.cpp 
	kde-qt.cpp 
	kchmviewwindow_qtextbrowser.cpp 
	kchmviewwindowmgr.cpp 
	kchmkeyeventfilter.cpp 
	kchmcontentswindow.cpp 
	kchmsetupdialog.cpp
	kde/kchmviewwindow_khtmlpart.cpp
	kde/kchmdbusiface.cpp
  )

# UI files
KDE4_ADD_UI_FILES( kchmviewerSources 
	tab_bookmarks.ui 
	tab_index.ui 
	tab_contents.ui 
	tab_search.ui 
	dialog_setup.ui
	dialog_topicselector.ui 
	window_main.ui 
	window_browser.ui
   )

# Resources
QT4_ADD_RESOURCES( kchmviewerResources resources/images.qrc )

KDE4_ADD_EXECUTABLE( kchmviewer ${kchmviewerSources} ${kchmviewerResources} )

TARGET_LINK_LIBRARIES( kchmviewer 
	chmfile 
	${LIBCHM_LIBRARY} 
	${KDE4_KDEUI_LIBS} 
	${KDE4_KHTML_LIBS}
	${KDE4_KFILE_LIBS}  )

INSTALL( TARGETS kchmviewer DESTINATION ${KDE4_BIN_INSTALL_DIR} )
INSTALL( FILES kde/kchmviewer.desktop DESTINATION ${KDE4_XDG_APPS_INSTALL_DIR} )
ADD_SUBDIRECTORY( kde )

