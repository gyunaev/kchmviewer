
cmake_minimum_required(VERSION 3.0)

# Project files
set(CPP_SOURCES
    ebook_chm.cpp
    ebook_epub.cpp
    ebook.cpp
    ebook_chm_encoding.cpp
    ebook_search.cpp
    helper_entitydecoder.cpp
    helper_search_index.cpp
    helperxmlhandler_epubcontainer.cpp
    helperxmlhandler_epubcontent.cpp
    helperxmlhandler_epubtoc.cpp
    )

set(MOC_HEADERS
    ebook_search.h
    helper_search_index.h
    )

if(${KDE4_FOUND})
    kde4_add_library(ebook STATIC ${CPP_SOURCES})
elseif(${QT4_FOUND})
    qt4_wrap_cpp(MOC_SOURCES ${MOC_HEADERS})
    add_library(ebook STATIC ${CPP_SOURCES} ${MOC_SOURCES})
else(${QT5_FOUND})
    qt5_wrap_cpp(MOC_SOURCES ${MOC_HEADERS})
    add_library(ebook STATIC ${CPP_SOURCES} ${MOC_SOURCES})
endif()

if(${QT4_FOUND})
    set(QT_LIB Qt4::QtCore Qt4::QtGui)
else(${QT5_FOUND})
    set(QT_LIB Qt5::Core Qt5::Widgets)
endif()

target_link_libraries(ebook chm libzip ${QT_LIB})
target_include_directories(ebook PUBLIC  "./")
target_compile_options(ebook PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Wall>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
)
set_target_properties(ebook PROPERTIES POSITION_INDEPENDENT_CODE ON)
