#include "ebook_url.h"

EbookURL::EbookURL()
	: QUrl()
{
}

EbookURL::EbookURL(const QString &url)
	: QUrl( url )
{
}
