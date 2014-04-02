#ifndef HELPERXMLHANDLER_EPUBCONTENT_H
#define HELPERXMLHANDLER_EPUBCONTENT_H

#include <QtXml/QXmlDefaultHandler>

class HelperXmlHandler_EpubContent : public QXmlDefaultHandler
{
	public:
		HelperXmlHandler_EpubContent();

		// Keep the tag-associated metadata
		QMap< QString, QString >	metadata;

		// Manifest storage, id -> href
		QMap< QString, QString >	manifest;

		// Spline storage
		QList< QString >			spine;

		// TOC (NCX) filename
		QString						tocname;

	private:
		enum State
		{
			STATE_NONE,
			STATE_IN_METADATA,
			STATE_IN_MANIFEST,
			STATE_IN_SPINE
		};

		bool startElement ( const QString & namespaceURI, const QString & localName, const QString & qName, const QXmlAttributes & atts );
		bool characters(const QString &ch);
		bool endElement(const QString &namespaceURI, const QString &localName, const QString &qName);

		// Tracking
		State		m_state;
		QString		m_tagname;
};

#endif // HELPERXMLHANDLER_EPUBCONTENT_H
