# Project name
PROJECT( kchmviewer )

# Init cmake
#SET( CMAKE_VERBOSE_MAKEFILE ON )
set( CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/")

# Necessary packages
FIND_PACKAGE( KDE4 REQUIRED )
FIND_PACKAGE( Libchm REQUIRED)

# Set compilation params
INCLUDE_DIRECTORIES( ${KDE4_INCLUDES}
		${CMAKE_SOURCE_DIR}/src
		${CMAKE_SOURCE_DIR}/lib/libchmfile )
ADD_DEFINITIONS( ${KDE4_DEFINITIONS} )
ADD_DEFINITIONS( -DUSE_KDE )

# Run in those subdirectories
ADD_SUBDIRECTORY( lib/libchmfile )
ADD_SUBDIRECTORY( lib/kio-msits )
ADD_SUBDIRECTORY( src )
ADD_SUBDIRECTORY( po )
