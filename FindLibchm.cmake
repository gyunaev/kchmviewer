# Tries to find libchm

FIND_PATH(LIBCHM_INCLUDE_DIR chm_lib.h /usr/include /usr/local/include)
FIND_LIBRARY(LIBCHM_LIBRARY NAMES chm PATH /usr/lib /usr/local/lib) 

IF (LIBCHM_INCLUDE_DIR AND LIBCHM_LIBRARY)
   SET(LIBCHM_FOUND TRUE)
ENDIF (LIBCHM_INCLUDE_DIR AND LIBCHM_LIBRARY)


IF (LIBCHM_FOUND)
   IF (NOT Libchm_FIND_QUIETLY)
      MESSAGE(STATUS "Found libchm: ${LIBCHM_LIBRARY}")
   ENDIF (NOT Libchm_FIND_QUIETLY)
ELSE (LIBCHM_FOUND)
   IF (Libchm_FIND_REQUIRED)
      MESSAGE(FATAL_ERROR "Could not find libchm. Please install chmlib-devel package (may be also called libchm-devel)")
   ENDIF (Libchm_FIND_REQUIRED)
ENDIF (LIBCHM_FOUND)
