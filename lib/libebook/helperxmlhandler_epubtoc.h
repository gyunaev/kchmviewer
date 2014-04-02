#ifndef HELPERXMLHANDLER_EPUBTOC_H
#define HELPERXMLHANDLER_EPUBTOC_H

#include <QtXml/QXmlDefaultHandler>
#include "ebook.h"

class HelperXmlHandler_EpubTOC : public QXmlDefaultHandler
{
	public:
		HelperXmlHandler_EpubTOC();

		QList< EBookIndexEntry >	entries;

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
};

#endif // HELPERXMLHANDLER_EPUBTOC_H
