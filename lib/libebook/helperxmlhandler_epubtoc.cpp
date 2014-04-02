#include <QtDebug>
#include "helperxmlhandler_epubtoc.h"

HelperXmlHandler_EpubTOC::HelperXmlHandler_EpubTOC()
{
	m_inNavMap = false;
	m_inText = false;
	m_indent = 0;
}

bool HelperXmlHandler_EpubTOC::startElement(const QString &, const QString &localName, const QString &, const QXmlAttributes &atts)
{
/*	qDebug() << "startElement " << " " << localName;

	for ( int i = 0; i < atts.count(); i++ )
		qDebug() << "    " << atts.localName(i) << " " << atts.value(i);
*/
	if ( localName == "navMap" )
	{
		m_inNavMap = true;
		return true;
	}

	if ( !m_inNavMap )
		return true;

	if ( localName == "navPoint" )
		m_indent++;

	if ( localName == "text" )
		m_inText = true;

	if ( localName == "content" )
	{
		int idx = atts.index( "src" );

		if ( idx == -1 )
			return false;

		m_lastId = atts.value( idx );
		checkNewTocEntry();
	}

	return true;
}

bool HelperXmlHandler_EpubTOC::characters(const QString &ch)
{
	if ( m_inText )
		m_lastTitle = ch;

	checkNewTocEntry();
//	qDebug() << "characters" << " " << ch;
	return true;
}

bool HelperXmlHandler_EpubTOC::endElement(const QString& , const QString &localName, const QString &)
{
//	qDebug() << "endElement" << " " << qName;

	if ( localName == "navMap" )
	{
		m_inNavMap = false;
		return true;
	}

	if ( localName == "navPoint" )
		m_indent--;

	if ( localName == "text" )
		m_inText = false;

	return true;
}

void HelperXmlHandler_EpubTOC::checkNewTocEntry()
{
	if ( !m_lastId.isEmpty() && !m_lastTitle.isEmpty() )
	{
		EBookIndexEntry entry;
		entry.name = m_lastTitle;
		entry.urls.push_back( m_lastId );
		entry.iconid = EBookIndexEntry::IMAGE_AUTO;
		entry.indent = m_indent - 1;

		entries.push_back( entry );

		//qDebug() << "TOC entry: " << m_lastId << " :" << m_lastTitle << " :" << m_indent - 1;

		m_lastId.clear();
		m_lastTitle.clear();
	}
}
