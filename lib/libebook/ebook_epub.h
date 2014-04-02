#ifndef EBOOK_EPUB_H
#define EBOOK_EPUB_H

#include <QString>
#include <QFile>

#include "ebook.h"
#include "zip.h"

class QXmlDefaultHandler;


class EBook_EPUB : public EBook
{
	public:
		EBook_EPUB();
		virtual ~EBook_EPUB();

		/*!
		 * \brief Attempts to load epub file.
		 * \param archiveName filename.
		 * \return EBook object on success, NULL on failure.
		 *
		 * Loads a epub file.
		 * \ingroup init
		 */
		bool	load( const QString& archiveName );

		/*!
		 * \brief Closes all the files, and frees the appropriate data.
		 * \ingroup init
		 */
		virtual void close();

		/*!
		 * \brief Gets the title name of the opened ebook.
		 * \return The name of the opened document, or an empty string if no ebook has been loaded.
		 * \ingroup information
		 */
		virtual QString title() const;

		/*!
		 * \brief Gets the default URL of the e-book which should be opened when the book it first open
		 *
		 * \return The home page name, with a '/' added in front and relative to
		 *         the root of the archive filesystem. If no book has been opened, returns "/".
		 * \ingroup information
		 */
		virtual QString homeUrl() const;

		/*!
		 * \brief Checks whether the Table of Contents is present in this file.
		 * \return true if it is available; false otherwise.
		 * \ingroup information
		 */
		virtual bool  hasTableOfContents() const;

		/*!
		 * \brief Checks whether the Index Table is present in this file.
		 * \return true if it is available; false otherwise.
		 * \ingroup information
		 */
		virtual bool  hasIndexTable() const;

		/*!
		 * \brief Checks whether the ebook supports change of encoding.
		 * \return true if does; false otherwise.
		 * \ingroup information
		 */
		virtual bool  supportsEncodingChange() const;

		/*!
		 * \brief Parses and fills up the Table of Contents (TOC)
		 * \param topics A pointer to the container which will store the parsed results.
		 *               Will be cleaned before parsing.
		 * \return true if the tree is present and parsed successfully, false otherwise.
		 *         The parser is built to be error-prone, however it still can abort with qFatal()
		 *         by really buggy files; please report a bug if the file is opened ok under Windows.
		 * \ingroup fileparsing
		 */
		virtual bool getTableOfContents( QList< EBookIndexEntry >& toc ) const;

		/*!
		 * \brief Parses the index table
		 * \param indexes A pointer to the container which will store the parsed results.
		 *               Will be cleaned before parsing.
		 * \return true if the tree is present and parsed successfully, false otherwise.
		 *         The parser is built to be error-prone, however it still can abort with qFatal()
		 *         by really buggy chm file; so far it never happened on indexes.
		 * \ingroup fileparsing
		 */
		virtual bool getIndex( QList< EBookIndexEntry >& index ) const;

		/*!
		 * \brief Retrieves the content associated with the url from the current ebook as QString.
		 * \param str A string where the retreived content should be stored.
		 * \param url An URL in chm file to retreive content from. Must be absolute.
		 * \return true if the content is successfully received; false otherwise. Note content may be an empty string.
		 *
		 * This function retreives the file content (mostly for HTML pages) from the ebook. Because the content
		 * in chm file might not be stored in Unicode, it will be recoded according to current encoding.
		 * Do not use for binary data.
		 *
		 * \sa setCurrentEncoding() currentEncoding() getFileContentAsBinary()
		 * \ingroup dataretrieve
		 */
		virtual bool getFileContentAsString( QString& str, const QString& url ) const;

		/*!
		 * \brief Retrieves the content from url in current chm file to QByteArray.
		 * \param data A data array where the retreived content should be stored.
		 * \param url An URL in chm file to retreive content from. Must be absolute.
		 * \return true if the content is successfully received; false otherwise.
		 *
		 * This function retreives the file content from the chm archive opened by load()
		 * function. The content is not encoded.
		 *
		 * \sa getFileContentAsString()
		 * \ingroup dataretrieve
		 */
		virtual bool getFileContentAsBinary( QByteArray& data, const QString& url ) const;

		/*!
		 * \brief Retrieves the content size.
		 * \param url An URL in ebook file to retreive content from. Must be absolute.
		 * \return the size; -1 in case of error.
		 *
		 * \ingroup dataretrieve
		 */
		virtual int getContentSize( const QString& url );

		/*!
		 * \brief Obtains the list of all the files (URLs) in current ebook archive. This is used in search
		 * and to dump the e-book content.
		 * \param files An array to store list of URLs (file names) present in chm archive.
		 * \return true if the enumeration succeed; false otherwise (I could hardly imagine a reason).
		 *
		 * \ingroup dataretrieve
		 */
		virtual bool enumerateFiles( QStringList& files );

		/*!
		 * \brief Gets the Title of the page referenced by url.
		 * \param url An URL in ebook file to get title from. Must be absolute.
		 * \return The title, or QString::null if the URL cannot be found or not a HTML page.
		 *
		 * \ingroup dataretrieve
		 */
		virtual QString	getTopicByUrl ( const QString& url );

		/*!
		 * \brief Gets the current ebook encoding (set or autodetected) as qtcodec
		 * \return The current encoding.
		 *
		 * \ingroup encoding
		 */
		virtual QString	currentEncoding() const;

		/*!
		 * \brief Sets the ebook encoding to use for TOC and content
		 * \param encoding An encoding to use.
		 *
		 * \ingroup encoding
		 */
		virtual bool setCurrentEncoding ( const char * encoding );

	private:
		// Parses the XML file using a specified parser
		bool	parseXML( const QString& uri, QXmlDefaultHandler * reader );

		// Parses the book description file. Fills up the ebook info
		bool	parseBookinfo();

		// ZIP archive fd and structs
		QFile			m_epubFile;
		struct zip *	m_zipFile;

		// Ebook info
		QString			m_title;

		// List of files in the ebook
		QStringList		m_ebookManifest;

		// Table of contents
		QList< EBookIndexEntry > m_tocEntries;

		// Map of URL-Title
		QMap< QString, QString>	m_urlTitleMap;
};

#endif // EBOOK_EPUB_H
