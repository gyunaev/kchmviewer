/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#ifndef INCLUDE_LIBCHMFILEIMPL_H
#define INCLUDE_LIBCHMFILEIMPL_H

#if defined (USE_PATCHED_CHMLIB)
	#include "chmlib-win32/chm_lib.h"
#else
	#include "chm_lib.h"
#endif

#include <sys/types.h>

#include "libchmfile.h"
#include "libchmtocimage.h"

#include <QPixmap>


//! Keeps the intermediate search result
class LCHMSearchProgressResult
{
	public:
		inline LCHMSearchProgressResult() {}
		inline LCHMSearchProgressResult( unsigned int t, unsigned int u ) : titleoff(t),urloff(u) {}
		
		QVector<quint64>	offsets;
		quint32				titleoff;
		quint32				urloff;
};

//! An array to keeps the intermediate search results
typedef QVector<LCHMSearchProgressResult>	LCHMSearchProgressResults;


//! CHM files processor; the implementation
class LCHMFileImpl
{
	public:
		LCHMFileImpl();
		~LCHMFileImpl();
		
		// Implementations for LCHMFile members
		bool 		loadFile( const QString& archiveName );
		void		closeAll();
		
		QString 	title() const	{ return encodeWithCurrentCodec( m_title ); }
		QString 	homeUrl() const	{ return encodeWithCurrentCodec( m_home ); }
		
		bool 		getFileContentAsString( QString * str, const QString& url, bool internal_encoding = false );
		bool 		getFileContentAsBinary( QByteArray * data, const QString& url ) const;
		bool		getFileContentAsBinary( QByteArray * data, const chmUnitInfo *ui ) const;
		bool 		getFileSize( unsigned int * size, const QString& url );
				
		bool		enumerateFiles( QStringList * files );
		QString		getTopicByUrl ( const QString& url )  const;
		
		const QPixmap * getBookIconPixmap( unsigned int imagenum );
		
		bool		setCurrentEncoding( const LCHMTextEncoding * encoding );
						
		//! Parse the HHC or HHS file, and fill the context (asIndex is false) or index (asIndex is true) array.
		bool  		parseFileAndFillArray (const QString& file, QVector< LCHMParsedEntry > * data, bool asIndex );
	
		/*!
		 * \brief Fast search using the $FIftiMain file in the .chm.
		 * \param text The text we're looking for.
		 * \param wholeWords Are we looking for whole words only?
		 * \param titlesOnly Are we looking for titles only?
		 * \param results A string-string hashmap that will hold
		 *               the results in case of successful search. The keys are
		 *               the URLs and the values are the page titles.
		 * \param phrase_search Indicates that word offset information should be kept.
		 * \return true if the search found something, false otherwise.
		*/
		bool searchWord( const QString& word, 
						 bool wholeWords, 
	   					 bool titlesOnly, 
		  				 LCHMSearchProgressResults& results, 
		                 bool phrase_search );

		/*!
		 *  \brief Finalize the search, resolve the matches, the and generate the results array.
		 * 	\param tempres Temporary search results from SearchWord.
		 * 	\param results A string-string hashmap that will hold the results in case of successful search.
		 *  The keys are the URLs and the values are the page titles.
		 */
		void getSearchResults( const LCHMSearchProgressResults& tempres, 
							   QStringList * results, 
		  					   unsigned int limit_results = 500 );

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

		//! Helper. Returns the $FIftiMain offset of leaf node or 0.
		unsigned int GetLeafNodeOffset(const QString& text,
									   unsigned int initialOffset,
									   unsigned int buffSize,
									   unsigned short treeDepth);

		//! Helper. Processes the word location code entries while searching.
		bool ProcessWLC(quint64 wlc_count,
						quint64 wlc_size,
						quint32 wlc_offset,
						unsigned char ds,
						unsigned char dr, 
						unsigned char cs,
						unsigned char cr, 
						unsigned char ls,
						unsigned char lr, 
						LCHMSearchProgressResults& results,
						bool phrase_search );

		//! Looks up as much information as possible from #WINDOWS/#STRINGS.
		bool getInfoFromWindows();

		//! Looks up as much information as possible from #SYSTEM.
		bool getInfoFromSystem();
	
		//! Fill the topic-url map
		void	fillTopicsUrlMap();
		
		//! Sets up textCodec
		void setupTextCodec (const char * name);

		//! Guess used text encoding, using m_detectedLCID and m_font. Set up m_textCodec
		bool guessTextEncoding ();

		//! Change the current CHM encoding for internal files and texts.
		//! Encoding could be either simple Qt codepage, or set like CP1251/KOI8, which allows to
		//! set up encodings separately for text (first) and internal files (second)
		bool  changeFileEncoding( const char *qtencoding );

		//! Convert the word, so it has an appropriate encoding
		QByteArray convertSearchWord ( const QString &src );

		/*!
		 * Helper procedure in TOC parsing, decodes the string between the quotes (first or last) with decoding HTML
		 * entities like &iacute;
		 */
		int findStringInQuotes (const QString& tag, int offset, QString& value, bool firstquote, bool decodeentities );

		/*!
		 * Decodes Unicode HTML entities according to current encoding.
		 */
		QString decodeEntity (const QString& entity );
		
		/*!
		 * \brief Returns the list of all available text encodings.
		 * \return A pointer to the beginning of the text encoding table. The table could be
		 *         enumerated until language == 0, which means end of table.
		 *
		 * \ingroup encoding
		 */
		static const LCHMTextEncoding	* 	getTextEncodingTable();

		/*!
		 * \brief Looks up for encoding by LCID
		 * \param lcid LCID to look up
		 * \return A pointer to encoding structure.
		 *
		 * \ingroup encoding
		 */
		static const LCHMTextEncoding * lookupByLCID( short lcid );
		
		/*!
		 * \brief Looks up for encoding by QtCodec
		 * \param qtcodec Qt text codec name to look up
		 * \return A pointer to encoding structure.
		 *
		 * \ingroup encoding
		 */
		static const LCHMTextEncoding * lookupByQtCodec( const QString& codec );
	
		/*!
		 * \brief Get the encoding index
		 * \param enc Encoding
		 * \return An index in encoding table. getTextEncodingTable() + i gets the encoding.
		 *
		 * \ingroup encoding
		 */
		static int getEncodingIndex( const LCHMTextEncoding * enc);
		
		/*!
		 * Normalizes path to search in internal arrays
		 */
		QString normalizeUrl (const QString& path ) const;

		/*!
		 * Parse binary TOC
		 */
		bool parseBinaryTOC( QVector< LCHMParsedEntry > * topics ) const;
		
		/*!
		 * Parse binary index
		 */
		bool parseBinaryIndex( QVector< LCHMParsedEntry > * topics ) const;

		//! Internal loader
		bool loadBinaryIndex( QVector< LCHMParsedEntry > * entries ) const;

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
  							  QVector< LCHMParsedEntry > * entries,
  							  int level ) const;

		/*!
		 * Check if an option was set in environment
		 */
		bool	hasOption( const QString& name ) const;

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
		const LCHMTextEncoding * m_currentEncoding;

		//! Map to decode HTML entitles like &acute; based on current encoding
		QMap<QString, QString>					m_entityDecodeMap;

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
		
		//! Indicates whether the built-in search is available. This is true only when m_lookupTablesValid
		//! is TRUE, and m_chmFIftiMain is resolved.
		bool			m_searchAvailable;

		//! pointer to /$FIftiMain
		chmUnitInfo	m_chmFIftiMain;
		
		//! Book TOC icon images storage
		LCHMTocImageKeeper	m_imagesKeeper;
		
		//! Map url->topic
		QMap< QString, QString >	m_url2topics;

		//! KCHMViewer debug options from environment
		QString			m_envOptions;
};

#endif // INCLUDE_LIBCHMFILEIMPL_H
