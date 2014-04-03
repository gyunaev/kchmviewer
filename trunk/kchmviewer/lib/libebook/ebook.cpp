#include "ebook.h"
#include "ebook_chm.h"
#include "ebook_epub.h"

const char * const INTERNAL_URL_SCHEME = "kchm";

EBook::EBook()
{
}


EBook::~EBook()
{
}

EBook * EBook::loadFile( const QString &archiveName )
{
	EBook_CHM * cbook = new EBook_CHM();

	if ( cbook->load( archiveName ) )
		return cbook;

	delete cbook;


	EBook_EPUB * ebook = new EBook_EPUB();

	if ( ebook->load( archiveName ) )
		return ebook;

	delete ebook;
	return 0;
}

