# Tries to find libzip

cmake_minimum_required(VERSION 3.0)

find_path(libzip_INCLUDE_DIR NAMES zip.h
    PATHS ${libzipDIR}
    PATH_SUFFIXES libzip/include include)

find_library(libzip_LIBRARY NAMES zip
    PATHS ${libzipDIR}
    PATH_SUFFIXES libzip/lib lib)

if (libzip_INCLUDE_DIR AND libzip_LIBRARY)
   set(libzip_FOUND TRUE)
endif ()


if (libzip_FOUND)
   if (NOT libzip_FIND_QUIETLY)
      message(STATUS "Found libzip: ${libzip_LIBRARY}")
   endif ()

   add_library(libzip SHARED IMPORTED)
   set_target_properties(libzip PROPERTIES
         INTERFACE_INCLUDE_DIRECTORIES ${libzip_INCLUDE_DIR}
         IMPORTED_LOCATION ${libzip_LIBRARY}
   )
else (libzip_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find libzip. Please install libzip and libzip-devel packages.\r"
          "  See https://libzip.org or https://github.com/nih-at/libzip")
endif ()
