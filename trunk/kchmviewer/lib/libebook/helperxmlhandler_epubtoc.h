#ifndef HELPERXMLHANDLER_EPUBTOC_H
#define HELPERXMLHANDLER_EPUBTOC_H

#include <QtXml/QXmlDefaultHandler>
#include "ebook_epub.h"

class HelperXmlHandler_EpubTOC : public QXmlDefaultHandler
{
	public:
		HelperXmlHandler_EpubTOC( EBook_EPUB * epub );

		QList< EBookTocEntry >	entries;

	private:
		// Overridden members
		bool startElement ( const QString & namespaceURI, const QString & localName, const QString & qName, const QXmlAttributes & atts );
		bool characters(const QString &ch);
		bool endElement(const QString &namespaceURI, const QString &localName, const QString &qName);
		void checkNewTocEntry();

		bool			m_inNavMap;
		bool			m_inText;
		unsigned int	m_indent;
		QString			m_lastId;
		QString			m_lastTitle;
		EBook_EPUB	*	m_epub;
};

#endif // HELPERXMLHANDLER_EPUBTOC_H
