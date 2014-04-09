/*
 *  Kchmviewer - a CHM and EPUB file viewer with broad language support
 *  Copyright (C) 2004-2014 George Yunaev, gyunaev@ulduzsoft.com
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "kde-qt.h"

#include <QtXml/QXmlSimpleReader>

#include "ebook_epub.h"
#include "helperxmlhandler_epubcontainer.h"
#include "helperxmlhandler_epubcontent.h"
#include "helperxmlhandler_epubtoc.h"

static const char * URL_SCHEME_EPUB = "epub";

EBook_EPUB::EBook_EPUB()
{
	m_zipFile = 0;
}

EBook_EPUB::~EBook_EPUB()
{
	close();
}

bool EBook_EPUB::load(const QString &archiveName)
{
	close();

	// We use QFile and zip_fdopen instead of zip_open because latter does not support Unicode file names
	m_epubFile.setFileName( archiveName );

	if ( !m_epubFile.open( QIODevice::ReadOnly ) )
	{
		qWarning("Could not open file %s: %s", qPrintable(archiveName), qPrintable( m_epubFile.errorString()));
		return false;
	}

	// Open the ZIP archive: http://www.nih.at/libzip/zip_fdopen.html
	int errcode;
	m_zipFile = zip_fdopen( m_epubFile.handle(), 0, &errcode );

	if ( !m_zipFile )
	{
		qWarning("Could not open file %s: error %d", qPrintable(archiveName), errcode);
		return false;
	}

	// Parse the book descriptor file
	if ( !parseBookinfo() )
		return false;

	return true;
}

void EBook_EPUB::close()
{
	if ( m_zipFile )
	{
		zip_close( m_zipFile );
		m_zipFile = 0;
	}

	if ( m_epubFile.isOpen() )
		m_epubFile.close();


}

bool EBook_EPUB::getFileContentAsString(QString &str, const QUrl &url) const
{
	return getFileAsString( str, urlToPath( url ) );
}

bool EBook_EPUB::getFileContentAsBinary(QByteArray &data, const QUrl &url) const
{
	return getFileAsBinary( data, urlToPath( url ) );
}

bool EBook_EPUB::enumerateFiles(QList<QUrl> &files)
{
	files = m_ebookManifest;
	return true;
}

QString EBook_EPUB::title() const
{
	return m_title;
}

QUrl EBook_EPUB::homeUrl() const
{
	return m_tocEntries[0].url;
}

bool EBook_EPUB::hasFeature(EBook::Feature code) const
{
    switch ( code )
    {
    case FEATURE_TOC:
        return true;

    case FEATURE_INDEX:
        return false;

    case FEATURE_ENCODING:
        return false;
    }

	return false;
}

bool EBook_EPUB::getTableOfContents( QList<EBookTocEntry> &toc ) const
{
	toc = m_tocEntries;
	return true;
}

bool EBook_EPUB::getIndex(QList<EBookIndexEntry> &) const
{
	return false;
}

QString EBook_EPUB::getTopicByUrl(const QUrl& url)
{
	if ( m_urlTitleMap.contains( url ) )
		return m_urlTitleMap[ url ];

	return "";
}

QString EBook_EPUB::currentEncoding() const
{
	abort();
}

bool EBook_EPUB::setCurrentEncoding(const char *)
{
	abort();
}

bool EBook_EPUB::isSupportedUrl(const QUrl &url)
{
	return url.scheme() == URL_SCHEME_EPUB;
}

bool EBook_EPUB::parseXML(const QString &uri, QXmlDefaultHandler * parser)
{
	QByteArray container;

	if ( !getFileAsBinary( container, uri ) )
	{
		qDebug("Failed to retrieve XML file %s", qPrintable( uri ) );
		return false;
	}

	// Use it as XML source
	QXmlInputSource source;
	source.setData( container );

	// Init the reader
	QXmlSimpleReader reader;
	reader.setContentHandler( parser );
	reader.setErrorHandler( parser );

	return reader.parse( source );
}

bool EBook_EPUB::parseBookinfo()
{
	// Parse the container.xml to find the content descriptor
	HelperXmlHandler_EpubContainer container_parser;

	if ( !parseXML( "META-INF/container.xml", &container_parser )
		 || container_parser.contentPath.isEmpty() )
		return false;

	// Parse the content.opf
	HelperXmlHandler_EpubContent content_parser;

	if ( !parseXML( container_parser.contentPath, &content_parser ) )
		return false;

	// At least title and the TOC must be present
	if ( !content_parser.metadata.contains("title") || content_parser.tocname.isEmpty() )
		return false;

	// All the files, including TOC, are relative to the container_parser.contentPath
	m_documentRoot.clear();
	int sep = container_parser.contentPath.lastIndexOf( '/' );

	if ( sep != -1 )
		m_documentRoot = container_parser.contentPath.left( sep + 1 );	// Keep the trailing slash

	// Parse the TOC
	HelperXmlHandler_EpubTOC toc_parser( this );

	if ( !parseXML( content_parser.tocname, &toc_parser ) )
		return false;

	// Get the data
	m_title = content_parser.metadata[ "title" ];

	// Copy the manifest information and fill up the other maps
	Q_FOREACH( EBookTocEntry e, toc_parser.entries )
	{
		// Add into url-title map
		m_urlTitleMap[ e.url ] = e.name;
		m_tocEntries.push_back( e );
	}

	// Move the manifest entries into the list
	Q_FOREACH( QString f, content_parser.manifest.values() )
		m_ebookManifest.push_back( pathToUrl( f ) );

	return true;
}

QUrl EBook_EPUB::pathToUrl(const QString &link) const
{
	QUrl url;
	url.setScheme( URL_SCHEME_EPUB );
	url.setHost( URL_SCHEME_EPUB );
	url.setPath( link );

	return url;
}

QString EBook_EPUB::urlToPath(const QUrl &link) const
{
	if ( link.scheme() == URL_SCHEME_EPUB )
		return link.path();

	return "";
}

bool EBook_EPUB::getFileAsString(QString &str, const QString &path) const
{
	QByteArray data;

	if ( !getFileAsBinary( data, path ) )
		return false;

	// I have never seen yet an UTF16 epub
	if ( data.startsWith("<?xml" ) )
	{
		int endxmltag = data.indexOf( "?>" );
		int utf16 = data.indexOf("UTF-16");

		if ( utf16 > 0 && utf16 < endxmltag )
		{
			QMessageBox::critical( 0,
								   ("Unsupported encoding"),
								   ("The encoding of this ebook is not supported yet. Please send it to gyunaev@ulduzsoft.com for support to be added") );
			return false;
		}
	}

	str = QString::fromUtf8( data );
	return true;
}

bool EBook_EPUB::getFileAsBinary(QByteArray &data, const QString &path) const
{
	// Retrieve the file size
	struct zip_stat fileinfo;
	QString completeUrl;

	if ( !path.isEmpty() && path[0] == '/' )
		completeUrl = m_documentRoot + path.mid( 1 );
	else
		completeUrl = m_documentRoot + path;

	//qDebug("URL requested: %s (%s)", qPrintable(path), qPrintable(completeUrl));

	// http://www.nih.at/libzip/zip_stat.html
	if ( zip_stat( m_zipFile, completeUrl.toUtf8().constData(), 0, &fileinfo) != 0 )
	{
		qDebug("File %s is not found in the archive", qPrintable(completeUrl));
		return false;
	}

	// Make sure the size field is valid
	if ( (fileinfo.valid & ZIP_STAT_SIZE) == 0 || (fileinfo.valid & ZIP_STAT_INDEX) == 0 )
		return false;

	// Open the file
	struct zip_file * file = zip_fopen_index( m_zipFile, fileinfo.index, 0 );

	if ( !file )
		return false;

	// Allocate the memory and read the file
	data.resize( fileinfo.size );

	// Could it return a positive number but not fileinfo.size???
	int ret = zip_fread( file, data.data(), fileinfo.size );
	if ( ret != (int) fileinfo.size )
	{
		zip_fclose( file );
		return false;
	}

	zip_fclose( file );
	return true;
}
