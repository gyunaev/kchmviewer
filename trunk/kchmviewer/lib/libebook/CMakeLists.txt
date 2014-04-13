# Project files
SET( libebookSources
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

KDE4_ADD_LIBRARY( ebook STATIC ${libebookSources} )

