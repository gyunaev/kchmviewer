#include "kde-qt.h"
#include "ebook_chm.h"
#include "ebook_chm_encoding.h"
#include "helper_entitydecoder.h"

#include "bitfiddle.h"
#include "helper_urlfactory.h"
#include "libchmtocimage.h"


// Big-enough buffer size for use with various routines.
#define BUF_SIZE 4096
#define COMMON_BUF_LEN 1025

#define TOPICS_ENTRY_LEN 16
#define URLTBL_ENTRY_LEN 12

//#define DEBUGPARSER(A)	qDebug A
#define DEBUGPARSER(A)



EBook_CHM::EBook_CHM()
{
	m_envOptions = getenv("KCHMVIEWEROPTS");
	m_chmFile = NULL;
	m_filename = m_font = QString::null;

	m_textCodec = 0;
	m_textCodecForSpecialFiles = 0;
	m_detectedLCID = 0;
	m_currentEncoding = "UTF-8";
	m_htmlEntityDecoder = 0;
}

EBook_CHM::~EBook_CHM()
{
	close();
}

void EBook_CHM::close()
{
	if ( m_chmFile == NULL )
		return;

	chm_close( m_chmFile );

	m_chmFile = NULL;
	m_filename = m_font = QString::null;

	m_home.clear();
	m_topicsFile.clear();
	m_indexFile.clear();

	m_textCodec = 0;
	m_textCodecForSpecialFiles = 0;
	m_detectedLCID = 0;
	m_currentEncoding = "UTF-8";
}

QString EBook_CHM::title() const
{
	return encodeWithCurrentCodec( m_title );
}

QString EBook_CHM::homeUrl() const
{
	return encodeWithCurrentCodec( m_home );
}

bool EBook_CHM::hasTableOfContents() const
{
	return m_tocAvailable;
}

bool EBook_CHM::hasIndexTable() const
{
	return m_indexAvailable;
}

bool EBook_CHM::parseTableOfContents( QList<EBookIndexEntry> &toc ) const
{
	return parseBinaryTOC( toc ) || parseFileAndFillArray( m_topicsFile, toc, false );
}

bool EBook_CHM::parseIndex(QList<EBookIndexEntry> &index) const
{
	return parseFileAndFillArray( m_indexFile, index, true );
}

bool EBook_CHM::getFileContentAsString( QString &str, const QString &url ) const
{
	return chmGetFileContentAsString( str, url );
}

bool EBook_CHM::getFileContentAsBinary( QByteArray &data, const QString &url ) const
{
	chmUnitInfo ui;

	if( !ResolveObject( url, &ui ) )
		return false;

	return chmGetFileContentAsBinary( data, &ui );
}

int EBook_CHM::getContentSize(const QString &url)
{
	chmUnitInfo ui;

	if( !ResolveObject( url, &ui ) )
		return -1;

	return ui.length;
}


bool EBook_CHM::chmGetFileContentAsBinary( QByteArray& data, const chmUnitInfo * ui ) const
{
	data.resize( ui->length );

	if ( RetrieveObject( ui, (unsigned char*) data.data(), 0, ui->length ) )
		return true;
	else
		return false;
}


bool EBook_CHM::load(const QString &archiveName)
{
	QString filename;

	// If the file has a file:// prefix, remove it
	if ( archiveName.startsWith( "file://" ) )
		filename = archiveName.mid( 7 ); // strip it
	else
		filename = archiveName;

	if( m_chmFile )
		close();

#if defined (USE_PATCHED_CHMLIB)
	m_chmFile = chm_open( (WCHAR*) filename.utf16() );
#else
	m_chmFile = chm_open( QFile::encodeName(filename) );
#endif

	if ( m_chmFile == NULL )
		return false;

	m_filename = filename;

	// Reset encoding
	m_textCodec = 0;
	m_textCodecForSpecialFiles = 0;
	m_currentEncoding = "UTF-8";

	// Get information from /#WINDOWS and /#SYSTEM files (encoding, title, context file and so)
	// and guess the encoding
	getInfoFromWindows();
	getInfoFromSystem();
	guessTextEncoding();

	// Check whether the search tables are present
	if ( ResolveObject("/#TOPICS", &m_chmTOPICS)
			&& ResolveObject("/#STRINGS", &m_chmSTRINGS)
			&& ResolveObject("/#URLTBL", &m_chmURLTBL)
			&& ResolveObject("/#URLSTR", &m_chmURLSTR) )
	{
		m_lookupTablesValid = true;
		fillTopicsUrlMap();
	}
	else
		m_lookupTablesValid = false;

	// Some CHM files have toc and index files, but do not set the name properly.
	// Some heuristics here.
	if ( m_topicsFile.isEmpty() && hasFile( "/toc.hhc" ) )
		m_topicsFile = "/toc.hhc";

	if ( m_indexFile.isEmpty() && hasFile( "/index.hhk" ) )
		m_indexFile = "/index.hhk";

	if ( !m_topicsFile.isEmpty() || ( m_lookupTablesValid && hasFile( "/#TOCIDX" ) ) )
		m_tocAvailable = true;
	else
		m_tocAvailable = false;

	if ( !m_indexFile.isEmpty() || ( m_lookupTablesValid && hasFile( "/$WWKeywordLinks/BTree" ) ) )
		m_indexAvailable = true;
	else
		m_indexAvailable = false;

	return true;
}

int EBook_CHM::findStringInQuotes (const QString& tag, int offset, QString& value, bool firstquote, bool decodeentities) const
{
	int qbegin = tag.indexOf ('"', offset);

	if ( qbegin == -1 )
		qFatal ("EBook_CHMImpl::findStringInQuotes: cannot find first quote in <param> tag: '%s'", qPrintable( tag ));

	int qend = firstquote ? tag.indexOf ('"', qbegin + 1) : tag.lastIndexOf ('"');

	if ( qend == -1 || qend <= qbegin )
		qFatal ("EBook_CHMImpl::findStringInQuotes: cannot find last quote in <param> tag: '%s'", qPrintable( tag ));

	// If we do not need to decode HTML entities, just return.
	if ( decodeentities )
	{
		QString htmlentity = QString::null;
		bool fill_entity = false;

		value.reserve (qend - qbegin); // to avoid multiple memory allocations

		for ( int i = qbegin + 1; i < qend; i++ )
		{
			if ( !fill_entity )
			{
				if ( tag[i] == '&' ) // HTML entity starts
					fill_entity = true;
				else
					value.append (tag[i]);
			}
			else
			{
				if ( tag[i] == ';' ) // HTML entity ends
				{
					// If entity is an ASCII code, just decode it
					QString decode = m_htmlEntityDecoder.decode( htmlentity );

					if ( decode.isNull() )
						break;

					value.append ( decode );
					htmlentity = QString::null;
					fill_entity = false;
				}
				else
					htmlentity.append (tag[i]);
			}
		}
	}
	else
		value = tag.mid (qbegin + 1, qend - qbegin - 1);

	return qend + 1;
}


bool EBook_CHM::parseFileAndFillArray( const QString& file, QList< EBookIndexEntry >& data, bool asIndex ) const
{
	QString src;
	const int MAX_NEST_DEPTH = 256;

	if ( !getFileContentAsString( src, file ) || src.isEmpty() )
		return false;

	ShowWaitCursor wc;

/*
	// Save the index for debugging purposes
	QFile outfile( "parsed.htm" );

	if ( outfile.open( QIODevice::WriteOnly ) )
	{
		QTextStream textstream( &outfile );
		textstream << src;
		outfile.close();
	}
*/

	EBookIndexEntry::Icon defaultimagenum = asIndex ? EBookIndexEntry::IMAGE_INDEX : EBookIndexEntry::IMAGE_AUTO;
	int pos = 0, indent = 0, root_indent_offset = 0;
	bool in_object = false, root_indent_offset_set = false;

	EBookIndexEntry entry;
	entry.iconid = defaultimagenum;

	// Split the HHC file by HTML tags
	int stringlen = src.length();

	while ( pos < stringlen && (pos = src.indexOf ('<', pos)) != -1 )
	{
		int i, word_end = 0;

		for ( i = ++pos; i < stringlen; i++ )
		{
			// If a " or ' is found, skip to the next one.
			if ( (src[i] == '"' || src[i] == '\'') )
			{
				// find where quote ends, either by another quote, or by '>' symbol (some people don't know HTML)
				int nextpos = src.indexOf (src[i], i+1);
				if ( nextpos == -1 	&& (nextpos = src.indexOf ('>', i+1)) == -1 )
				{
					qWarning ("EBook_CHMImpl::ParseHhcAndFillTree: corrupted TOC: %s", qPrintable( src.mid(i) ));
					return false;
				}

				i =  nextpos;
			}
			else if ( src[i] == '>'  )
				break;
			else if ( !src[i].isLetterOrNumber() && src[i] != '/' && !word_end )
				word_end = i;
		}

		QString tagword, tag = src.mid (pos, i - pos);

		if ( word_end )
			tagword = src.mid (pos, word_end - pos).toLower();
		else
			tagword = tag.toLower();

//		qDebug ("tag: '%s', tagword: '%s'\n", qPrintable( tag ), qPrintable( tagword ) );

		// <OBJECT type="text/sitemap"> - a topic entry
		if ( tagword == "object" && tag.indexOf ("text/sitemap", 0, Qt::CaseInsensitive ) != -1 )
			in_object = true;
		else if ( tagword == "/object" && in_object )
		{
			// a topic entry closed. Add a tree item
			if ( entry.name.isEmpty() && entry.urls.isEmpty() )
			{
				qWarning ("EBook_CHMImpl::ParseAndFillTopicsTree: <object> tag is parsed, but both name and url are empty.");
			}
			else
			{
				// If the name is empty, use the URL as name
				if ( entry.name.isEmpty() )
					entry.name = entry.urls[0];

				if ( !root_indent_offset_set )
				{
					root_indent_offset_set = true;
					root_indent_offset = indent;

					if ( root_indent_offset > 1 )
						qWarning("CHM has improper index; root indent offset is %d", root_indent_offset);
				}

				// Trim the entry name
				entry.name = entry.name.trimmed();

				int real_indent = indent - root_indent_offset;

				entry.indent = real_indent;
				data.push_back( entry );
			}

			entry.name = QString::null;
			entry.urls.clear();
			entry.iconid = defaultimagenum;
			in_object = false;
		}
		else if ( tagword == "param" && in_object )
		{
			// <param name="Name" value="First Page">
			int offset; // strlen("param ")
			QString name_pattern = "name=", value_pattern = "value=";
			QString pname, pvalue;

			if ( (offset = tag.indexOf (name_pattern, 0, Qt::CaseInsensitive )) == -1 )
				qFatal ("EBook_CHMImpl::ParseAndFillTopicsTree: bad <param> tag '%s': no name=\n", qPrintable( tag ));

			// offset+5 skips 'name='
			offset = findStringInQuotes (tag, offset + name_pattern.length(), pname, TRUE, FALSE);
			pname = pname.toLower();

			if ( (offset = tag.indexOf(value_pattern, offset, Qt::CaseInsensitive )) == -1 )
				qFatal ("EBook_CHMImpl::ParseAndFillTopicsTree: bad <param> tag '%s': no value=\n", qPrintable( tag ));

			// offset+6 skips 'value='
			findStringInQuotes (tag, offset + value_pattern.length(), pvalue, FALSE, TRUE);

			//qDebug ("<param>: name '%s', value '%s'", qPrintable( pname ), qPrintable( pvalue ));

			if ( pname == "name" || pname == "keyword" )
			{
				// Some help files contain duplicate names, where the second name is empty. Work it around by keeping the first one
				if ( !pvalue.isEmpty() )
					entry.name = pvalue;
			}
			else if ( pname == "merge" )
			{
				// MERGE implementation is experimental
				QString mergeurl = HelperUrlFactory::makeURLabsoluteIfNeeded( pvalue );
				QString mergecontent;

				if ( getFileContentAsString( mergecontent, mergeurl ) && !mergecontent.isEmpty() )
				{
					qWarning( "MERGE is used in index; the implementation is experimental. Please let me know if it works" );

					// Merge the read value into the current parsed file.
					// To save memory it is done in a kinda hacky way:
					src = mergecontent + src.mid( i );
					pos = 0;
					stringlen = src.length();
				}
				else
					qWarning( "MERGE is used in index but file %s was not found in CHM archive", qPrintable(mergeurl) );
			}
			else if ( pname == "local" )
			{
				// Check for URL duplication
				QString url = HelperUrlFactory::makeURLabsoluteIfNeeded( pvalue );

				if ( !entry.urls.contains( url ) )
					entry.urls.push_back( url );
			}
			else if ( pname == "see also" && asIndex && entry.name != pvalue )
				entry.urls.push_back (":" + pvalue);
			else if ( pname == "imagenumber" )
			{
				bool bok;
				int imgnum = pvalue.toInt (&bok);

				if ( bok && imgnum >= 0 && imgnum < EBookIndexEntry::MAX_BUILTIN_ICONS )
					entry.iconid = (EBookIndexEntry::Icon) imgnum;
			}
		}
		else if ( tagword == "ul" ) // increase indent level
		{
			// Fix for buggy help files
			if ( ++indent >= MAX_NEST_DEPTH )
				qFatal("EBook_CHMImpl::ParseAndFillTopicsTree: max nest depth (%d) is reached, error in help file", MAX_NEST_DEPTH);

			// This intended to fix <ul><ul>, which was seen in some buggy chm files,
			// and brokes rootentry[indent-1] check
		}
		else if ( tagword == "/ul" ) // decrease indent level
		{
			if ( --indent < root_indent_offset )
				indent = root_indent_offset;

			DEBUGPARSER(("</ul>: new intent is %d\n", indent - root_indent_offset));
		}

		pos = i;
	}

	return true;
}

bool EBook_CHM::ResolveObject(const QString& fileName, chmUnitInfo *ui) const
{
	return m_chmFile != NULL
			&& ::chm_resolve_object(m_chmFile, qPrintable( fileName ), ui) ==
			CHM_RESOLVE_SUCCESS;
}


bool EBook_CHM::hasFile(const QString & fileName) const
{
	chmUnitInfo ui;

	return m_chmFile != NULL
			&& ::chm_resolve_object(m_chmFile, qPrintable( fileName ), &ui) ==
			CHM_RESOLVE_SUCCESS;
}


size_t EBook_CHM::RetrieveObject(const chmUnitInfo *ui, unsigned char *buffer,
								LONGUINT64 fileOffset, LONGINT64 bufferSize) const
{
	return ::chm_retrieve_object(m_chmFile, const_cast<chmUnitInfo*>(ui),
								 buffer, fileOffset, bufferSize);
}

bool EBook_CHM::getInfoFromWindows()
{
#define WIN_HEADER_LEN 0x08
	unsigned char buffer[BUF_SIZE];
	unsigned int factor;
	chmUnitInfo ui;
	long size = 0;

	if ( ResolveObject("/#WINDOWS", &ui) )
	{
		if ( !RetrieveObject(&ui, buffer, 0, WIN_HEADER_LEN) )
			return false;

		unsigned int entries = get_int32_le( (unsigned int *)(buffer) );
		unsigned int entry_size = get_int32_le( (unsigned int *)(buffer + 0x04) );

		QVector<unsigned char> uptr(entries * entry_size);
		unsigned char* raw = (unsigned char*) uptr.data();

		if ( !RetrieveObject (&ui, raw, 8, entries * entry_size) )
			return false;

		if( !ResolveObject ("/#STRINGS", &ui) )
			return false;

		for ( unsigned int i = 0; i < entries; ++i )
		{
			unsigned int offset = i * entry_size;

			unsigned int off_title = get_int32_le( (unsigned int *)(raw + offset + 0x14) );
			unsigned int off_home = get_int32_le( (unsigned int *)(raw + offset + 0x68) );
			unsigned int off_hhc = get_int32_le( (unsigned int *)(raw + offset + 0x60) );
			unsigned int off_hhk = get_int32_le( (unsigned int *)(raw + offset + 0x64) );

			factor = off_title / 4096;

			if ( size == 0 )
				size = RetrieveObject(&ui, buffer, factor * 4096, BUF_SIZE);

			if ( size && off_title )
				m_title = QByteArray( (const char*) (buffer + off_title % 4096) );

			if ( factor != off_home / 4096)
			{
				factor = off_home / 4096;
				size = RetrieveObject (&ui, buffer, factor * 4096, BUF_SIZE);
			}

			if ( size && off_home )
				m_home = QByteArray("/") + QByteArray( (const char*) buffer + off_home % 4096);

			if ( factor != off_hhc / 4096)
			{
				factor = off_hhc / 4096;
				size = RetrieveObject(&ui, buffer, factor * 4096, BUF_SIZE);
			}

			if ( size && off_hhc )
				m_topicsFile = QByteArray("/") + QByteArray((const char*) buffer + off_hhc % 4096);

			if ( factor != off_hhk / 4096)
			{
				factor = off_hhk / 4096;
				size = RetrieveObject (&ui, buffer, factor * 4096, BUF_SIZE);
			}

			if ( size && off_hhk )
				m_indexFile = QByteArray("/") + QByteArray((const char*) buffer + off_hhk % 4096);
		}
	}
	return true;
}



bool EBook_CHM::getInfoFromSystem()
{
	unsigned char buffer[BUF_SIZE];
	chmUnitInfo ui;

	int index = 0;
	unsigned char* cursor = NULL, *p;
	unsigned short value = 0;
	long size = 0;

	// Run the first loop to detect the encoding. We need this, because title could be
	// already encoded in user encoding. Same for file names
	if ( !ResolveObject ("/#SYSTEM", &ui) )
		return false;

	// Can we pull BUFF_SIZE bytes of the #SYSTEM file?
	if ( (size = RetrieveObject (&ui, buffer, 4, BUF_SIZE)) == 0 )
		return false;

	buffer[size - 1] = 0;

	// First loop to detect the encoding
	for ( index = 0; index < (size - 1 - (long)sizeof(unsigned short)) ;)
	{
		cursor = buffer + index;
		value = UINT16ARRAY(cursor);

		switch(value)
		{
			case 0:
				index += 2;
				cursor = buffer + index;

				if(m_topicsFile.isEmpty())
					m_topicsFile = QByteArray("/") + QByteArray((const char*) buffer + index + 2);

				break;

			case 1:
				index += 2;
				cursor = buffer + index;

				if(m_indexFile.isEmpty())
					m_indexFile = QByteArray("/") + QByteArray((const char*)buffer + index + 2);
				break;

			case 2:
				index += 2;
				cursor = buffer + index;

				if(m_home.isEmpty() || m_home == "/")
					m_home = QByteArray("/") + QByteArray((const char*) buffer + index + 2);
				break;

			case 3:
				index += 2;
				cursor = buffer + index;
				m_title = QByteArray( (const char*) (buffer + index + 2) );
				break;

			case 4:
				index += 2;
				cursor = buffer + index;

				p = buffer + index + 2;
				m_detectedLCID = (short) (p[0] | (p[1]<<8));

				break;

			case 6:
				index += 2;
				cursor = buffer + index;

				if ( m_topicsFile.isEmpty() )
				{
					QString topicAttempt = "/", tmp;
					topicAttempt += QString ((const char*) buffer +index +2);

					tmp = topicAttempt + ".hhc";

					if ( ResolveObject( tmp, &ui) )
						m_topicsFile = qPrintable( tmp );

					tmp = topicAttempt + ".hhk";

					if ( ResolveObject( tmp, &ui) )
						m_indexFile = qPrintable( tmp );
				}
				break;

			case 16:
				index += 2;
				cursor = buffer + index;

				m_font = QString ((const char*) buffer + index + 2);
				break;

			default:
				index += 2;
				cursor = buffer + index;
		}

		value = UINT16ARRAY(cursor);
		index += value + 2;
	}

	return true;
}


bool EBook_CHM::chmGetFileContentAsString( QString& str, const QString & url, bool internal_encoding ) const
{
	QByteArray buf;

	if ( getFileContentAsBinary( buf, url ) )
	{
		unsigned int length = buf.size();

		if ( length > 0 )
		{
			buf.resize( length + 1 );
			buf [length] = '\0';

			str = internal_encoding ? (QString)( buf.constData() ) :  encodeWithCurrentCodec( buf.constData() );
			return true;
		}
	}

	return false;
}

QString EBook_CHM::getTopicByUrl( const QString & url )
{
	QMap< QString, QString >::const_iterator it = m_url2topics.find( url );

	if ( it == m_url2topics.end() )
		return QString::null;

	return it.value();
}


static int chm_enumerator_callback( struct chmFile*, struct chmUnitInfo *ui, void *context )
{
	((QStringList*) context)->push_back( ui->path );
	return CHM_ENUMERATOR_CONTINUE;
}

bool EBook_CHM::enumerateFiles( QStringList& files )
{
	files.clear();
	return chm_enumerate( m_chmFile, CHM_ENUMERATE_ALL, chm_enumerator_callback, &files );
}

const QPixmap * EBook_CHM::getBookIconPixmap( EBookIndexEntry::Icon imagenum )
{
	return m_imagesKeeper.getImage( imagenum );
}

QString EBook_CHM::currentEncoding() const
{
	return m_currentEncoding;
}

bool EBook_CHM::setCurrentEncoding( const char * encoding )
{
	m_currentEncoding = encoding;
	return changeFileEncoding( encoding );
}

bool EBook_CHM::guessTextEncoding()
{
	if ( !m_detectedLCID )
	{
		qFatal ("Could not detect LCID");
		return false;
	}

	QString enc = Ebook_CHM_Encoding::guessByLCID( m_detectedLCID );

	if ( changeFileEncoding ( enc ) )
	{
		m_currentEncoding = enc;
		return true;
	}

	return false;
}

bool EBook_CHM::changeFileEncoding( const QString& qtencoding  )
{
	// Encoding could be either simple Qt codepage, or set like CP1251/KOI8, which allows to
	// set up encodings separately for text (first) and internal files (second)
	int p = qtencoding.indexOf( '/' );

	if ( p != -1 )
	{
		QString global = qtencoding.left( p );
		QString special = qtencoding.mid( p + 1 );

		m_textCodec = QTextCodec::codecForName( global.toUtf8() );

		if ( !m_textCodec )
		{
			qWarning( "Could not set up Text Codec for encoding '%s'", qPrintable( global ) );
			return false;
		}

		m_textCodecForSpecialFiles = QTextCodec::codecForName( special.toUtf8() );

		if ( !m_textCodecForSpecialFiles )
		{
			qWarning( "Could not set up Text Codec for encoding '%s'", qPrintable( special ) );
			return false;
		}
	}
	else
	{
		m_textCodecForSpecialFiles = m_textCodec = QTextCodec::codecForName( qtencoding.toUtf8() );

		if ( !m_textCodec )
		{
			qWarning( "Could not set up Text Codec for encoding '%s'", qPrintable( qtencoding ) );
			return false;
		}
	}

	m_htmlEntityDecoder.changeEncoding( m_textCodec );
	return true;
}


void EBook_CHM::fillTopicsUrlMap()
{
	if ( !m_lookupTablesValid )
		return;

	// Read those tables
	QVector<unsigned char> topics( m_chmTOPICS.length ), urltbl( m_chmURLTBL.length ), urlstr( m_chmURLSTR.length ), strings( m_chmSTRINGS.length );

	if ( !RetrieveObject( &m_chmTOPICS, (unsigned char*) topics.data(), 0, m_chmTOPICS.length )
	|| !RetrieveObject( &m_chmURLTBL, (unsigned char*) urltbl.data(), 0, m_chmURLTBL.length )
	|| !RetrieveObject( &m_chmURLSTR, (unsigned char*) urlstr.data(), 0, m_chmURLSTR.length )
	|| !RetrieveObject( &m_chmSTRINGS, (unsigned char*) strings.data(), 0, m_chmSTRINGS.length ) )
		return;

	for ( unsigned int i = 0; i < m_chmTOPICS.length; i += TOPICS_ENTRY_LEN )
	{
		unsigned int off_title = get_int32_le( (unsigned int *)(topics.data() + i + 4) );
		unsigned int off_url = get_int32_le( (unsigned int *)(topics.data() + i + 8) );
		off_url = get_int32_le( (unsigned int *)( urltbl.data() + off_url + 8) ) + 8;

		QString url = HelperUrlFactory::makeURLabsoluteIfNeeded( (const char*) urlstr.data() + off_url );

		if ( off_title < (unsigned int)strings.size() )
			m_url2topics[url] = encodeWithCurrentCodec ( (const char*) strings.data() + off_title );
		else
			m_url2topics[url] = "Untitled";
	}
}


bool EBook_CHM::parseBinaryTOC( QList< EBookIndexEntry >& toc ) const
{
	if ( !m_lookupTablesValid )
		return false;

	QByteArray tocidx, topics, urltbl, urlstr, strings;

	// Read the index tables
	if ( !getFileContentAsBinary( tocidx, "/#TOCIDX" )
	|| !getFileContentAsBinary( topics, "/#TOPICS" )
	|| !getFileContentAsBinary( urltbl, "/#URLTBL" )
	|| !getFileContentAsBinary( urlstr, "/#URLSTR" )
	|| !getFileContentAsBinary( strings, "/#STRINGS" ) )
		return false;

	// Shamelessly stolen from xchm
	if ( !RecurseLoadBTOC( tocidx, topics, urltbl, urlstr, strings, UINT32ARRAY( tocidx.data() ),  toc, 0 ) )
	{
		qWarning("Failed to parse binary TOC, fallback to text-based TOC");
		toc.clear();
		return false;
	}

	return true;
}


//
// This piece of code was based on the one in xchm written by  Razvan Cojocaru <razvanco@gmx.net>
//
bool EBook_CHM::RecurseLoadBTOC( const QByteArray& tocidx,
									const QByteArray& topics,
									const QByteArray& urltbl,
									const QByteArray& urlstr,
									const QByteArray& strings,
									int offset,
									QList< EBookIndexEntry >& entries,
									int level ) const
{
	while ( offset )
	{
		// If this is end of TOCIDX, return.
		if ( tocidx.size() < offset + 20 )
			return true;

		unsigned int flags = UINT32ARRAY( tocidx.data() + offset + 4 );
		int index = UINT32ARRAY( tocidx.data() + offset + 8 );

		if ( (flags & 0x04) || (flags & 0x08))
		{
			QString name, value;

			if ( (flags & 0x08) == 0 )
			{
				if ( strings.size() < index + 1 )
				{
					qWarning("EBook_CHM::RecurseLoadBTOC: invalid name index (%d) for book TOC entry!", index );
					return false;
				}

				name = encodeWithCurrentCodec( strings.data() + index);
			}
			else
			{
				if ( topics.size() < (index * 16) + 12 )
				{
					qWarning("EBook_CHM::RecurseLoadBTOC: invalid name index (%d) for local TOC entry!", index );
					return false;
				}

				int tocoffset = (int) UINT32ARRAY(topics.data()+ (index * 16) + 4);

				if ( strings.size() < tocoffset + 1 )
				{
					qWarning("EBook_CHM::RecurseLoadBTOC: invalid name tocoffset (%d) for TOC entry!", tocoffset );
					return false;
				}

				if ( tocoffset < 0 )
					name.clear();
				else
					name = encodeWithCurrentCodec( strings.data() + tocoffset );

				// #URLTBL index
				tocoffset = (int) UINT32ARRAY( topics.data() + (index * 16) + 8 );

				if ( tocoffset < 0 || urltbl.size() < tocoffset + 12 )
				{
					qWarning("EBook_CHM::RecurseLoadBTOC: invalid url index (%d) for TOC entry!", tocoffset );
					return false;
				}

				tocoffset = (int) UINT32ARRAY(urltbl.data() + tocoffset + 8);

				if ( tocoffset < 0 || urlstr.size() < tocoffset )
				{
					qWarning("EBook_CHM::RecurseLoadBTOC: invalid url offset (%d) for TOC entry!", tocoffset );
					return false;
				}

				value = encodeWithCurrentCodec( urlstr.data() + tocoffset + 8 );
			}

			EBookIndexEntry entry;
			entry.name = name.trimmed();

			if ( !entry.name.isEmpty() )
			{
				if ( !value.isEmpty() )
					entry.urls.push_back( HelperUrlFactory::makeURLabsoluteIfNeeded( value ) );

				entry.iconid = EBookIndexEntry::IMAGE_AUTO;
				entry.indent = level;
				entries.push_back( entry );
			}
		}

		if ( flags & 0x04 )
		{
			// book
			if ( tocidx.size() < offset + 24 )
			{
				qWarning("EBook_CHM::RecurseLoadBTOC: invalid child entry offset (%d)", offset );
				return false;
			}

			unsigned int childoffset = UINT32ARRAY( tocidx.data() + offset + 20 );

			if ( childoffset )
			{
				if ( !RecurseLoadBTOC( tocidx, topics, urltbl, urlstr, strings, childoffset, entries, level + 1 ) )
					return false;
			}
		}

		offset = UINT32ARRAY( tocidx.data() + offset + 0x10 );
	}

	return true;
}



bool EBook_CHM::hasOption(const QString & name) const
{
	if ( !m_envOptions.isEmpty() && m_envOptions.contains( name ) )
		return true;

	return false;
}


//
// This piece of code was based on the one in xchm written by Razvan Cojocaru <razvanco@gmx.net>
//
bool EBook_CHM::parseBinaryIndex( QList< EBookIndexEntry >& entries ) const
{
	if ( !m_lookupTablesValid )
		return false;

	if ( hasOption("nobintables") )
		return false;

	if ( !loadBinaryIndex( entries ) )
	{
		qWarning("Failed to parse binary index, fallback to text-based index");
		entries.clear();
		return false;
	}

	return true;
}


QString EBook_CHM::getBtreeString( const QByteArray& btidx, unsigned long * offset, unsigned short * spaceLeft ) const
{
	QByteArray string;
	unsigned short tmp;

	while ( 1 )
	{
		// accumulate the name
		if ( (unsigned) btidx.size() < *offset + sizeof(unsigned short) )
			return QString();

		tmp = UINT16ARRAY( btidx.data() + *offset );
		*offset += sizeof(unsigned short);
		*spaceLeft -= sizeof(unsigned short);

		if ( tmp == 0x00 )
			break;

		string.push_back( tmp );
	}

	return encodeWithCurrentCodec( string ).trimmed();
}


bool EBook_CHM::loadBinaryIndex( QList< EBookIndexEntry >& entries ) const
{
	QByteArray btidx, topics, urltbl, urlstr, strings;

	// Read the index tables
	if ( !getFileContentAsBinary( btidx, "/$WWKeywordLinks/BTree" )
	|| !getFileContentAsBinary( topics, "/#TOPICS" )
	|| !getFileContentAsBinary( urltbl, "/#URLTBL" )
	|| !getFileContentAsBinary( urlstr, "/#URLSTR" )
	|| !getFileContentAsBinary( strings, "/#STRINGS" ) )
		return false;

	// Make sure we have enough entries in tree
	if ( btidx.size() < 88 )
	{
		qWarning("EBook_CHM::loadBinaryIndex: BTree is too small" );
		return false;
	}

	unsigned long offset = 0x4c;
	int next = -1;
	unsigned short freeSpace, spaceLeft;
	const short blockSize = 2048;
	bool found_item = false;

	do
	{
		if ( (unsigned) btidx.size() < offset + 12 )
			break;

		freeSpace = UINT16ARRAY( btidx.data() + offset );
		next = INT32ARRAY( btidx.data() + offset + 8 );
		spaceLeft = blockSize - 12;
		offset += 12;

		while ( spaceLeft > freeSpace )
		{
			QString value;
			EBookIndexEntry entry;

			entry.name = getBtreeString( btidx, &offset, &spaceLeft );

			if ( entry.name.isEmpty() )
			{
				qWarning("EBook_CHM::loadBinaryIndex: cannot parse name" );
				return false;
			}

			if ( (unsigned) btidx.size() < offset + 16 )
			{
				qWarning("EBook_CHM::loadBinaryIndex: index is terminated by name" );
				return false;
			}

			unsigned short seeAlso = UINT16ARRAY(btidx.data() + offset);
			unsigned int numTopics = UINT32ARRAY(btidx.data() + offset + 0xc);
			offset += 16;
			spaceLeft -= 16;

			if ( seeAlso )
			{
				QString seealso = getBtreeString( btidx, &offset, &spaceLeft );

				if ( entry.name != seealso )
					entry.urls.push_back( ":" + seealso );
			}
			else
			{
				for ( unsigned int i = 0; i < numTopics && spaceLeft > freeSpace; ++i )
				{
					if ( (unsigned) btidx.size() < offset + sizeof(unsigned int) )
					{
						qWarning("EBook_CHM::loadBinaryIndex: premature url termination" );
						return false;
					}

					unsigned int index = UINT32ARRAY( btidx.data() + offset );

					// #URLTBL index
					unsigned int tocoffset = UINT32ARRAY( topics.data() + (index * 16) + 8 );

					if ( (unsigned) urltbl.size() < tocoffset + 12 )
					{
						qWarning("EBook_CHM::loadBinaryIndex: invalid url index (%d) for TOC entry!", tocoffset );
						return false;
					}

					tocoffset = UINT32ARRAY(urltbl.data() + tocoffset + 8);

					if ( (unsigned) urlstr.size() < tocoffset )
					{
						qWarning("EBook_CHM::loadBinaryIndex: invalid url offset (%d) for TOC entry!", tocoffset );
						return false;
					}

					QString url = encodeWithCurrentCodec( urlstr.data() + tocoffset + 8 );
					entry.urls.push_back( HelperUrlFactory::makeURLabsoluteIfNeeded( url ) );
					offset += sizeof(unsigned int);
					spaceLeft -= sizeof(unsigned int);
				}
			}

			entry.name = entry.name.trimmed();

			if ( !entry.name.isEmpty() )
			{
				entry.iconid = EBookIndexEntry::IMAGE_INDEX;
				entry.indent = 0;
				found_item = true;
				entries.push_back( entry );
			}

			if ( (unsigned) btidx.size() < offset + 8 )
			{
				qWarning("EBook_CHM::loadBinaryIndex: binary index is gone" );
				return false;
			}

			offset += 8;
			spaceLeft -= 8;
		}

		offset += spaceLeft;

	} while ( next != -1 );

	return found_item;
}
