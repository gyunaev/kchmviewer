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

#ifndef EBOOK_EPUB_H
#define EBOOK_EPUB_H

#include <QString>
#include <QStringList>
#include <QFile>
#include <QUrl>

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
		virtual QUrl homeUrl() const;

		/*!
         * \brief Checks whether the specific feature is present in this file.
         * \return true if it is available; false otherwise.
         * \ingroup information
         */
        virtual bool  hasFeature( Feature code ) const;

		/*!
		 * \brief Parses and fills up the Table of Contents (TOC)
		 * \param topics A pointer to the container which will store the parsed results.
		 *               Will be cleaned before parsing.
		 * \return true if the tree is present and parsed successfully, false otherwise.
		 *         The parser is built to be error-prone, however it still can abort with qFatal()
		 *         by really buggy files; please report a bug if the file is opened ok under Windows.
		 * \ingroup fileparsing
		 */
		virtual bool getTableOfContents( QList< EBookTocEntry >& toc ) const;

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
		virtual bool getFileContentAsString( QString& str, const QUrl& url ) const;

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
		virtual bool getFileContentAsBinary( QByteArray& data, const QUrl& url ) const;

		/*!
		 * \brief Obtains the list of all the files (URLs) in current ebook archive. This is used in search
		 * and to dump the e-book content.
		 * \param files An array to store list of URLs (file names) present in chm archive.
		 * \return true if the enumeration succeed; false otherwise (I could hardly imagine a reason).
		 *
		 * \ingroup dataretrieve
		 */
		virtual bool enumerateFiles( QList<QUrl>& files );

		/*!
		 * \brief Gets the Title of the page referenced by url.
		 * \param url An URL in ebook file to get title from. Must be absolute.
		 * \return The title, or QString::null if the URL cannot be found or not a HTML page.
		 *
		 * \ingroup dataretrieve
		 */
		virtual QString	getTopicByUrl ( const QUrl& url );

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

		/*!
		 * \brief Checks if this kind of URL is supported by the ebook format (i.e. could be passed to ebook functions)
		 * \param url The url to check
		 */
		virtual bool isSupportedUrl( const QUrl& url );

		// Converts the string to the ebook-specific URL format
		QUrl pathToUrl( const QString & link ) const;

		// Extracts the path component from the URL
		QString urlToPath( const QUrl& link ) const;

	private:
		// Parses the XML file using a specified parser
		bool	parseXML( const QString& uri, QXmlDefaultHandler * reader );

		// Parses the book description file. Fills up the ebook info
		bool	parseBookinfo();

		// Get file content from path
		bool	getFileAsString( QString& str, const QString& path ) const;
		bool	getFileAsBinary( QByteArray& data, const QString& path ) const;

		// ZIP archive fd and structs
		QFile			m_epubFile;
		struct zip *	m_zipFile;

		// Ebook info
		QString			m_title;
		QString			m_documentRoot;

		// List of files in the ebook
		QList<QUrl>		m_ebookManifest;

		// Table of contents
		QList< EBookTocEntry >	m_tocEntries;

		// Map of URL-Title
		QMap< QUrl, QString>	m_urlTitleMap;
};

#endif // EBOOK_EPUB_H
