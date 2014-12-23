HEADERS += 	bitfiddle.h \
    ebook_chm.h \
    ebook_epub.h \
    ebook.h \
    ebook_chm_encoding.h \
    ebook_search.h \
    helper_entitydecoder.h \
    helper_search_index.h \
    helperxmlhandler_epubcontainer.h \
    helperxmlhandler_epubcontent.h \
    helperxmlhandler_epubtoc.h
SOURCES +=  \
    ebook_chm.cpp \
    ebook_epub.cpp \
    ebook.cpp \
    ebook_chm_encoding.cpp \
    ebook_search.cpp \
    helper_entitydecoder.cpp \
    helper_search_index.cpp \
    helperxmlhandler_epubcontainer.cpp \
    helperxmlhandler_epubcontent.cpp \
    helperxmlhandler_epubtoc.cpp
TARGET = ebook
CONFIG += warn_on \
		  qt \
		  staticlib
TEMPLATE = lib
INCLUDEPATH += ../../src
QT += widgets
win32-g++*: {
	DEFINES += USE_PATCHED_CHMLIB
}
