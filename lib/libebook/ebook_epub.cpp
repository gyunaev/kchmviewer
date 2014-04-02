#include "kde-qt.h"

#include <QtXml/QXmlSimpleReader>

#include "ebook_epub.h"
#include "helperxmlhandler_epubcontainer.h"
#include "helperxmlhandler_epubcontent.h"
#include "helperxmlhandler_epubtoc.h"

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

bool EBook_EPUB::getFileContentAsString(QString &str, const QString &url) const
{
	//FIXME! utf16
	QByteArray data;

	if ( !getFileContentAsBinary( data, url ) )
		return false;

	// I have never seen yet an UTF16 epub
	if ( data.startsWith("<?xml" ) )
	{
		int endxmltag = data.indexOf( "?>" );

		if ( data.indexOf("UTF-16") < endxmltag )
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

bool EBook_EPUB::getFileContentAsBinary(QByteArray &data, const QString &url) const
{
	// Retrieve the file size
	struct zip_stat fileinfo;

	// http://www.nih.at/libzip/zip_stat.html
	if ( zip_stat( m_zipFile, url.toUtf8().constData(), 0, &fileinfo) != 0 )
	{
		qDebug("File %s is not found in the archive", qPrintable(url));
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
		qDebug( "zip_fread read %d vs %ld", ret, fileinfo.size );
		zip_fclose( file );
		return false;
	}

	zip_fclose( file );
	return true;
}

int EBook_EPUB::getContentSize(const QString &url)
{
	// Retrieve the file size
	struct zip_stat fileinfo;

	// http://www.nih.at/libzip/zip_stat.html
	if ( zip_stat( m_zipFile, url.toUtf8().constData(), 0, &fileinfo) != 0 )
		return -1;

	// Make sure the size field is valid
	if ( (fileinfo.valid & ZIP_STAT_SIZE) == 0 || (fileinfo.valid & ZIP_STAT_INDEX) == 0 )
		return -1;

	return fileinfo.size;
}

bool EBook_EPUB::enumerateFiles(QStringList &files)
{
	for ( int i = 0; i < zip_get_num_entries( m_zipFile, 0 ); i++ )
		files.push_back( QString::fromUtf8( zip_get_name( m_zipFile, i, ZIP_FL_ENC_GUESS) ) );

	return true;
}


QString EBook_EPUB::title() const
{
	return m_title;
}

QString EBook_EPUB::homeUrl() const
{
	return m_tocEntries[0].urls[0];
}

bool EBook_EPUB::hasTableOfContents() const
{
	// EPUB always has TOC
	return true;
}

bool EBook_EPUB::hasIndexTable() const
{
	// EPUB never has index
	return false;
}

bool EBook_EPUB::supportsEncodingChange() const
{
	return false;
}

bool EBook_EPUB::getTableOfContents(QList<EBookIndexEntry> &toc) const
{
	toc = m_tocEntries;
	return true;
}

bool EBook_EPUB::getIndex(QList<EBookIndexEntry> &) const
{
	return false;
}

QString EBook_EPUB::getTopicByUrl(const QString &url)
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

bool EBook_EPUB::parseXML(const QString &uri, QXmlDefaultHandler * parser)
{
	QByteArray container;

	if ( !getFileContentAsBinary( container, uri ) )
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
	QString contentDir = "";
	int sep = container_parser.contentPath.lastIndexOf( '/' );

	if ( sep != -1 )
		contentDir = container_parser.contentPath.left( sep + 1 );

	// Parse the TOC
	HelperXmlHandler_EpubTOC toc_parser;

	if ( !parseXML( contentDir + content_parser.tocname, &toc_parser ) )
		return false;

	// Get the data
	m_title = content_parser.metadata[ "title" ];

	// Copy the manifest information and fill up the other maps
	Q_FOREACH( EBookIndexEntry e, toc_parser.entries )
	{
		// Convert the url into absolute
		if ( !contentDir.isEmpty() )
			e.urls[0] = contentDir + e.urls[0];

		// Add into url-title map
		m_urlTitleMap[ e.urls[0] ] = e.name;
		m_tocEntries.push_back( e );
	}

	// Move the manifest entries into the list
	Q_FOREACH( QString f, content_parser.manifest.values() )
		m_ebookManifest.push_back( contentDir + f );

	return true;
}
