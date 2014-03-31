#include "ebook_epub.h"

EBook_EPUB::EBook_EPUB()
{
}

EBook_EPUB::~EBook_EPUB()
{

}

bool EBook_EPUB::load(const QString &archiveName)
{

}

void EBook_EPUB::close()
{

}

QString EBook_EPUB::title() const
{

}

QString EBook_EPUB::homeUrl() const
{

}

bool EBook_EPUB::hasTableOfContents() const
{

}

bool EBook_EPUB::hasIndexTable() const
{

}

bool EBook_EPUB::parseTableOfContents(QList<EBookIndexEntry> &toc) const
{

}

bool EBook_EPUB::parseIndex(QList<EBookIndexEntry> &index) const
{

}

bool EBook_EPUB::getFileContentAsString(QString &str, const QString &url) const
{

}

bool EBook_EPUB::getFileContentAsBinary(QByteArray &data, const QString &url) const
{

}

int EBook_EPUB::getContentSize(const QString &url)
{

}

bool EBook_EPUB::enumerateFiles(QStringList &files)
{

}

QString EBook_EPUB::getTopicByUrl(const QString &url)
{

}

const QPixmap *EBook_EPUB::getBookIconPixmap(EBookIndexEntry::Icon imagenum)
{
	// EPUB does not support icons
	return 0;
}

QString EBook_EPUB::currentEncoding() const
{

}

bool EBook_EPUB::setCurrentEncoding(const char *encoding)
{

}
