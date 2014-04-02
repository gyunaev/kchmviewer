#include "helperxmlhandler_epubcontainer.h"

bool HelperXmlHandler_EpubContainer::startElement(const QString &, const QString &, const QString &qName, const QXmlAttributes &atts)
{
	if ( qName == "rootfile" )
	{
		int idx = atts.index( "full-path" );

		if ( idx == -1 )
			return false;

		contentPath = atts.value( idx );
	}

	return true;
}
