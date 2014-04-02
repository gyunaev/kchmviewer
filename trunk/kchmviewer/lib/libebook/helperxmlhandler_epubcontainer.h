#ifndef HELPERXMLHANDLER_EPUBCONTAINER_H
#define HELPERXMLHANDLER_EPUBCONTAINER_H

#include <QtXml/QXmlDefaultHandler>

class HelperXmlHandler_EpubContainer : public QXmlDefaultHandler
{
	public:
		// Overridden members
		bool startElement ( const QString & namespaceURI, const QString & localName, const QString & qName, const QXmlAttributes & atts );

		// The content path
		QString	contentPath;
};

#endif // HELPERXMLHANDLER_EPUBCONTAINER_H
