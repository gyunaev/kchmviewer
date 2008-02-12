# File generated by kdevelop's qmake manager. 
# ------------------------------------------- 
# Subdir relative project main directory: ./src/qgrafix
# Target is a library:  qgrafix

HEADERS += 	bitfiddle.h \
			libchmfile.h \
			libchmfileimpl.h \
			libchmtextencoding.h \
			libchmtocimage.h \
			libchmurlfactory.h \
 	lchmsearchengine.h \
 	lchmsearchengine_impl.h \
 	lchmsearchengine_indexing.h
SOURCES +=  libchmfile.cpp \
			libchmfileimpl.cpp \
			libchmfile_search.cpp \
			libchmtextencoding.cpp \
			libchmtocimage.cpp \
  lchmsearchengine.cpp \
  lchmsearchengine_impl.cpp \
  lchmsearchengine_indexing.cpp
TARGET = chmfile
CONFIG += warn_on \
		  qt \
		  staticlib
TEMPLATE = lib
INCLUDEPATH += ../../src
