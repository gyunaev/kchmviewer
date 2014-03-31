#include "textencodings.h"

typedef struct
{
	const char * language;
	const char * qtcodec;
} TextEncodingEntry;

static const TextEncodingEntry text_encoding_table [] =
{
	{
		"Arabic",
		"CP1256"
	},

	{
		"Baltic",
		"CP1257"
	},

	{
		"Central European",
		"CP1250"
	},

	{
		"Chinese Simplified",
		"GB18030"
	},

	{
		"Chinese Simplified",
		"GBK"
	},

	{
		"Chinese Simplified",
		"GB2313"
	},

	{
		"Chinese Traditional",
		"Big5"
	},

	{
		"Chinese Traditional",
		"Big5-HKSCS",
	},

	{
		"Cyrillic",
		"CP1251",
	},

	{
		"Cyrillic",
		"KOI8-R",
	},

	{
		"Cyrillic Broken",
		"CP1251/KOI8-R",
	},

	{
		"Cyrillic Broken",
		"KOI8-R/CP1251",
	},

	{
		"Greek",
		"CP1253",
	},

	{
		"Hebrew",
		"CP1255",
	},

	{
		"Japanese",
		"Shift-JIS",
	},

	{
		"Japanese",
		"eucJP",
	},

	{
		"Japanese",
		"JIS7",
	},

	{
		"Korean",
		"eucKR",
	},

	{
		"Tamil",
		"TSCII",
	},

	{
		"Thai",
		"TIS-620",
	},

	{
		"Ukrainian",
		"KOI8-U"
	},

	{
		"Turkish",
		"CP1254"
	},

	{
		"Vietnamese",
		"CP1258"
	},

	{
		"Unicode",
		"UTF-8"
	},

	{
		"Unicode",
		"UTF-16",
	},

	{
		"Western",
		"CP1252",
	},

	{ 0, 0 }
};


TextEncodings::TextEncodings()
{
}

void TextEncodings::getSupported(QStringList &languages, QStringList &qtcodecs)
{
	for ( const TextEncodingEntry * e = text_encoding_table; e->language; e++ )
	{
		languages.push_back( e->language );
		qtcodecs.push_back( e->qtcodec );
	}
}

QString TextEncodings::languageForCodec(const QString &qtcodec)
{
	for ( const TextEncodingEntry * e = text_encoding_table; e->language; e++ )
	{
		if ( e->qtcodec == qtcodec )
			return e->language;
	}

	return "Unknown";
}
