# Project files
SET( libchmfileSources
        libchmfile.cpp
        libchmfileimpl.cpp
        libchmfile_search.cpp
        libchmsearchengine.cpp
        libchmsearchengine_impl.cpp
        libchmsearchengine_indexing.cpp
        libchmtextencoding.cpp
        libchmtocimage.cpp 
  )

KDE4_ADD_LIBRARY( chmfile STATIC ${libchmfileSources} )

