#ifndef HELPER_ENTITYDECODER_H
#define HELPER_ENTITYDECODER_H

#include <QMap>
#include <QString>

//
// This helper class decodes the Unicode HTML entities into the Unicode characters
//
class HelperEntityDecoder
{
	public:
		// Initialization with the specific decoder
		HelperEntityDecoder( QTextCodec * encoder = 0 );

		// Used when the encoding changes
		void	changeEncoding( QTextCodec * encoder = 0 );


		// The decoder function
		QString decode( const QString& entity ) const;

	private:
		// Map to decode HTML entitles like &acute; based on current encoding, initialized upon the first use
		QMap<QString, QString>	m_entityDecodeMap;
};

#endif // HELPER_ENTITYDECODER_H
