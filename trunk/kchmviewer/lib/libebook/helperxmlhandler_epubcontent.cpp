#include "helperxmlhandler_epubcontent.h"

HelperXmlHandler_EpubContent::HelperXmlHandler_EpubContent()
{
	m_state = STATE_NONE;
}

bool HelperXmlHandler_EpubContent::startElement(const QString &, const QString &localName, const QString &, const QXmlAttributes &atts)
{
	// <metadata> tag contains the medatada which goes into m_metadata
	if ( localName == "metadata" )
		m_state = STATE_IN_METADATA;
	else if ( localName == "manifest" )
		m_state = STATE_IN_MANIFEST;
	else if ( localName == "spine" )
		m_state = STATE_IN_SPINE;
	// Now handle the states
	else if ( m_state == STATE_IN_METADATA ) // we don't need to store the first 'metadata' here
		m_tagname = localName;
	else if ( m_state == STATE_IN_MANIFEST && localName == "item" )
	{
		int idx_id = atts.index( "id" );
		int idx_href = atts.index( "href" );
		int idx_mtype = atts.index( "media-type" );

		if ( idx_id == -1 || idx_href == -1 || idx_mtype == -1 )
			return false;

		manifest[ atts.value( idx_id ) ] = atts.value( idx_href );

		if ( atts.value( idx_mtype ) == "application/x-dtbncx+xml" )
			tocname = atts.value( idx_href );

		//qDebug() << "MANIFEST: " << atts.value( idx_id ) << "->" << atts.value( idx_href );
	}
	else if ( m_state == STATE_IN_SPINE && localName == "itemref" )
	{
		int idx = atts.index( "idref" );

		if ( idx == -1 )
			return false;

		spine.push_back( atts.value( idx ) );
		//qDebug() << "SPINE: " << atts.value( idx );
	}

	return true;
}

bool HelperXmlHandler_EpubContent::characters(const QString &ch)
{
	if ( m_state == STATE_IN_METADATA && !m_tagname.isEmpty() && !ch.trimmed().isEmpty() )
	{
		// Some metadata may be duplicated; we concantenate them with |
		if ( metadata.contains( m_tagname ) )
		{
			metadata[ m_tagname ].append( "|" );
			metadata[ m_tagname ].append( ch.trimmed() );
		}
		else
			metadata[ m_tagname ] = ch.trimmed();

		//qDebug() << "METATAG: " << m_tagname << " " << metadata[ m_tagname ];
	}

	return true;
}

bool HelperXmlHandler_EpubContent::endElement(const QString &, const QString &, const QString &qName)
{
	if ( qName == "manifest" || qName == "metadata" || qName == "spine" )
		m_state = STATE_NONE;

	return true;
}
