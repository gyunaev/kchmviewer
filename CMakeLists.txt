# Project name
PROJECT( kchmviewer )

# Init cmake
set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/")

# Necessary packages
FIND_PACKAGE( KDE4 REQUIRED )
FIND_PACKAGE( Libchm REQUIRED)

# libzip
FIND_PATH(LIBZIP_INCLUDE_DIR zip.h)
FIND_LIBRARY(LIBZIP_LIBRARY NAMES zip)

IF (LIBZIP_INCLUDE_DIR AND LIBZIP_LIBRARY)
	MESSAGE(STATUS "Found libzip: ${LIBZIP_LIBRARY}")
ELSE ()
	MESSAGE(FATAL_ERROR "Could not find libzip. Please install libzip and libzip-devel packages")
ENDIF ()

# Set compilation params
INCLUDE_DIRECTORIES( ${KDE4_INCLUDES}
		${CMAKE_SOURCE_DIR}/src
		${CMAKE_SOURCE_DIR}/lib/libebook )
ADD_DEFINITIONS( ${KDE4_DEFINITIONS} )
ADD_DEFINITIONS( -DUSE_KDE )

# Run in those subdirectories
ADD_SUBDIRECTORY( lib/libebook )
ADD_SUBDIRECTORY( src )
ADD_SUBDIRECTORY( po )
ADD_SUBDIRECTORY( packages )
