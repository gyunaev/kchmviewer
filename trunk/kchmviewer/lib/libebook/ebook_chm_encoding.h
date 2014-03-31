#ifndef EBOOK_CHM_ENCODING_H
#define EBOOK_CHM_ENCODING_H

#include <QString>

class Ebook_CHM_Encoding
{
	public:
		static QString guessByLCID( unsigned short lcid );
};

#endif // EBOOK_CHM_ENCODING_H
