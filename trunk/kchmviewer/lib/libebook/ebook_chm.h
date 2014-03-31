#ifndef EBOOK_CHM_H
#define EBOOK_CHM_H

#if defined (USE_PATCHED_CHMLIB)
	#include "chmlib-win32/chm_lib.h"
#else
	#include "chm_lib.h"
#endif

#include <QMap>
#include <QString>

#include "ebook.h"
#include "helper_entitydecoder.h"


class EBook_CHM : public EBook
{
	public:
		EBook_CHM();
		~EBook_CHM();

		/*!
		 * \brief Attempts to load chm file.
		 * \param archiveName filename.
		 * \return EBook object on success, NULL on failure.
		 *
		 * Loads a CHM file. For CHM files it could internally load more than one file,
		 * if files linked to this one are present locally (like MSDN).
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
		 * \brief Parses and fills up the Table of Contents (TOC)
		 * \param topics A pointer to the container which will store the parsed results.
		 *               Will be cleaned before parsing.
		 * \return true if the tree is present and parsed successfully, false otherwise.
		 *         The parser is built to be error-prone, however it still can abort with qFatal()
		 *         by really buggy files; please report a bug if the file is opened ok under Windows.
		 * \ingroup fileparsing
		 */
		virtual bool parseTableOfContents( QList< EBookIndexEntry >& toc ) const;

		/*!
		 * \brief Parses the index table
		 * \param indexes A pointer to the container which will store the parsed results.
		 *               Will be cleaned before parsing.
		 * \return true if the tree is present and parsed successfully, false otherwise.
		 *         The parser is built to be error-prone, however it still can abort with qFatal()
		 *         by really buggy chm file; so far it never happened on indexes.
		 * \ingroup fileparsing
		 */
		virtual bool parseIndex( QList< EBookIndexEntry >& index ) const;

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
		virtual QString		getTopicByUrl ( const QString& url );

		/*!
		 * \brief Gets the appropriate CHM pixmap icon (there are no icons in EPUB).
		 * \param imagenum The image number from TOC.
		 * \return The pixmap to show in TOC tree or NULL if there is no icon associated.
		 *
		 * \ingroup dataretrieve
		 */
		virtual const QPixmap * getBookIconPixmap(EBookIndexEntry::Icon imagenum );

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
		// Members

		//! Pointer to the chmlib structure
		chmFile	*	m_chmFile;

		//! Opened file name
		QString  	m_filename;

		//! Home url, got from CHM file
		QByteArray  m_home;

		//! Context tree filename. Got from CHM file
		QByteArray 	m_topicsFile;

		//! Index filename. Got from CHM file
		QByteArray	m_indexFile;

		//! Chm Title. Got from CHM file
		QByteArray	m_title;

		// Localization stuff
		//! LCID from CHM file, used in encoding detection
		short			m_detectedLCID;

		//! font charset from CHM file, used in encoding detection
		QString 		m_font;

		//! Chosen text codec
		QTextCodec	*	m_textCodec;
		QTextCodec	*	m_textCodecForSpecialFiles;

		//! Current encoding
		QString			m_currentEncoding;

		//! TRUE if /#TOPICS, /#STRINGS, /#URLTBL and  /#URLSTR are resolved, and the members below are valid
		bool		m_lookupTablesValid;

		//! pointer to /#TOPICS
		chmUnitInfo	m_chmTOPICS;

		//! pointer to /#STRINGS
		chmUnitInfo	m_chmSTRINGS;

		//! pointer to /#URLTBL
		chmUnitInfo	m_chmURLTBL;

		//! pointer to /#URLSTR
		chmUnitInfo	m_chmURLSTR;

		//! Indicates whether TOC, either binary or text, is available.
		bool			m_tocAvailable;

		//! Indicates whether index, either binary or text, is available.
		bool			m_indexAvailable;

		//! Built-in CHM icons
		QVector< QPixmap> m_chmBuiltinIcons;

		//! Map url->topic
		QMap< QString, QString >	m_url2topics;

		//! KCHMViewer debug options from environment
		QString			m_envOptions;

		//! HTML entity decoder
		HelperEntityDecoder		m_htmlEntityDecoder;

		//! Looks up fileName in the archive.
		bool hasFile( const QString& fileName ) const;

		//! Looks up fileName in the archive.
		bool ResolveObject( const QString& fileName, chmUnitInfo *ui ) const;

		//!  Retrieves an uncompressed chunk of a file in the .chm.
		size_t RetrieveObject( const chmUnitInfo *ui, unsigned char *buffer, LONGUINT64 fileOffset, LONGINT64 bufferSize) const;

		//! Encode the string with the currently selected text codec, if possible. Or return as-is, if not.
		inline QString encodeWithCurrentCodec( const QByteArray& str) const
		{
			return (m_textCodec ? m_textCodec->toUnicode( str.constData () ) : str);
		}

		//! Encode the string with the currently selected text codec, if possible. Or return as-is, if not.
		inline QString encodeWithCurrentCodec (const char * str) const
		{
			return (m_textCodec ? m_textCodec->toUnicode( str ) : (QString) str);
		}

		//! Encode the string from internal files with the currently selected text codec, if possible.
		//! Or return as-is, if not.
		inline QString encodeInternalWithCurrentCodec (const QString& str) const
		{
			return (m_textCodecForSpecialFiles ? m_textCodecForSpecialFiles->toUnicode( qPrintable(str) ) : str);
		}

		//! Encode the string from internal files with the currently selected text codec, if possible.
		//! Or return as-is, if not.
		inline QString encodeInternalWithCurrentCodec (const char * str) const
		{
			return (m_textCodecForSpecialFiles ? m_textCodecForSpecialFiles->toUnicode (str) : (QString) str);
		}

		//! Helper. Translates from Win32 encodings to generic wxWidgets ones.
		const char * GetFontEncFromCharSet (const QString& font) const;

		//! Parse the HHC or HHS file, and fill the context (asIndex is false) or index (asIndex is true) array.
		bool  		parseFileAndFillArray (const QString& file, QList< EBookIndexEntry >& data, bool asIndex ) const;

		bool 		chmGetFileContentAsString( QString& str, const QString& url, bool internal_encoding = false ) const;

		bool		chmGetFileContentAsBinary( QByteArray& data, const chmUnitInfo *ui) const;

		/*!
		 * Parse binary TOC
		 */
		bool parseBinaryTOC( QList< EBookIndexEntry >& data ) const;

		/*!
		 * Parse binary index
		 */
		bool parseBinaryIndex( QList< EBookIndexEntry >& data ) const;

		//! Internal loader
		bool loadBinaryIndex( QList< EBookIndexEntry >& data ) const;

		//! btree string parser
		QString getBtreeString( const QByteArray& btidx, unsigned long * offset, unsigned short * spaceLeft ) const;

		/*!
		 * Recursively parse and fill binary TOC
		 */
		bool RecurseLoadBTOC( const QByteArray& tocidx,
							  const QByteArray& topics,
							  const QByteArray& urltbl,
							  const QByteArray& urlstr,
							  const QByteArray& strings,
							  int offset,
							  QList< EBookIndexEntry >& data,
							  int level ) const;

		/*!
		 * Helper procedure in TOC parsing, decodes the string between the quotes (first or last) with decoding HTML
		 * entities like &iacute;
		 */
		int findStringInQuotes (const QString& tag, int offset, QString& value, bool firstquote, bool decodeentities ) const;
		bool getInfoFromWindows();
		bool getInfoFromSystem();
		bool changeFileEncoding(const QString &qtencoding);
		bool guessTextEncoding();
		void fillTopicsUrlMap();
		bool hasOption(const QString &name) const;
};

#endif // EBOOK_CHM_H
