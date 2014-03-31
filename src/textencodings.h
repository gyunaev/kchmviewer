#ifndef TEXTENCODINGS_H
#define TEXTENCODINGS_H

#include <QStringList>

class TextEncodings
{
	public:
		TextEncodings();

		static void getSupported( QStringList& languages, QStringList& qtcodecs );
		static QString languageForCodec( const QString& qtcodec );
};

#endif // TEXTENCODINGS_H
