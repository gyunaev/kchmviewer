
cmake_minimum_required(VERSION 3.0)
# Need to include generated files.
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Project files
set(CPP_SOURCES
    config.cpp
    dbus_interface.cpp
    dialog_chooseurlfromlist.cpp
    dialog_setup.cpp
    kde-qt.cpp
    main.cpp
    mainwindow.cpp
    recentfiles.cpp
    settings.cpp
    tab_bookmarks.cpp
    tab_contents.cpp
    tab_index.cpp
    tab_search.cpp
    viewwindowmgr.cpp
    navigationpanel.cpp
    checknewversion.cpp
    toolbarmanager.cpp
    toolbareditor.cpp
    dataprovider_qwebkit.cpp
    textencodings.cpp
    treeitem_toc.cpp
    treeitem_index.cpp
    )

set(MOC_HEADERS
    dbus_interface.h
    dialog_chooseurlfromlist.h
    dialog_setup.h
    mainwindow.h
    recentfiles.h
    tab_bookmarks.h
    tab_contents.h
    tab_index.h
    tab_search.h
    viewwindowmgr.h
    navigationpanel.h
    checknewversion.h
    toolbarmanager.h
    toolbareditor.h
    )

# UI files
set(UIS
    dialog_about.ui
    dialog_setup.ui
    dialog_topicselector.ui
    mainwindow.ui
    navigatorpanel.ui
    tab_bookmarks.ui
    tab_contents.ui
    tab_index.ui
    tab_search.ui
    toolbareditor.ui
    window_browser.ui
    )

if (${QT_USE_WEBENGINE} AND NOT ${QT4_FOUND})
    set(CPP_SOURCES ${CPP_SOURCES} viewwindow_webengine.cpp)
    set(MOC_HEADERS ${MOC_HEADERS} viewwindow_webengine.h)
    set(QT_WEB_PACKAGE Qt5::WebEngine Qt5::WebEngineWidgets)
else ()
    set(CPP_SOURCES ${CPP_SOURCES} viewwindow_webkit.cpp)
    set(MOC_HEADERS ${MOC_HEADERS} viewwindow_webkit.h)
    set(QT_WEB_PACKAGE Qt5::WebKit Qt5::WebKitWidgets)
endif ()

if(${QT4_FOUND})
    qt4_add_resources(RSRCS resources/images.qrc)
else(${QT5_FOUND})
    qt5_add_resources(RSRCS resources/images.qrc)
endif()

if(${KDE4_FOUND})
    kde4_add_ui_files(CPP_SOURCES ${UIS})
    kde4_add_executable(kchmviewer ${CPP_SOURCES} ${RSRCS})
    target_link_libraries(kchmviewer
        ebook
        chm
        ${KDE4_KDEUI_LIBS}
        ${QT_QTWEBKIT_LIBRARY}
        ${KDE4_KFILE_LIBS}
        $<$<BOOL:UNIX>:X11>
        )

    install(TARGETS kchmviewer DESTINATION ${KDE4_BIN_INSTALL_DIR})
elseif(${QT4_FOUND})
    qt4_wrap_ui(UI_SOURCES ${UIS})
    qt4_wrap_cpp(MOC_SOURCES ${MOC_HEADERS})
    add_executable(kchmviewer ${CPP_SOURCES} ${RSRCS} ${UI_SOURCES} ${MOC_SOURCES})
    target_link_libraries(kchmviewer
        ebook
        chm
        Qt4::QtCore
        Qt4::QtDBus
        Qt4::QtNetwork
        Qt4::QtWebKit
        Qt4::QtGui
        Qt4::QtXml
        $<$<BOOL:UNIX>:X11>
        )
else(${QT5_FOUND})
    qt5_wrap_ui(UI_SOURCES ${UIS})
    qt5_wrap_cpp(MOC_SOURCES ${MOC_HEADERS})
    add_executable(kchmviewer ${CPP_SOURCES} ${RSRCS} ${UI_SOURCES} ${MOC_SOURCES})
    target_link_libraries(kchmviewer
        ebook
        chm
        Qt5::Core
        Qt5::DBus
        Qt5::Network
        Qt5::PrintSupport
        ${QT_WEB_PACKAGE}
        Qt5::Widgets
        Qt5::Xml
        )
endif()

target_compile_options(kchmviewer PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Wall>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
)
