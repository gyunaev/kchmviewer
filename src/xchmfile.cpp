/***************************************************************************
 *   Copyright (C) 2005 by Georgy Yunaev                                   *
 *   tim@krasnogorsk.ru                                                    *
 *                                                                         *
 *   Copyright (C) 2003  Razvan Cojocaru <razvanco@gmx.net>                *
 *   XML-RPC/Context ID code contributed by Eamon Millman / PCI Geomatics  *
 *   <millman@pcigeomatics.com>                                            *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

//FIXME: <A HREF="ms-its:file name.chm::/topic.htm">
//FIXME: support for not only book and page icons 
//FIXME: support for custom icons
//FIXME: support for information types


#include <qmessagebox.h> 
#include <qstring.h>
#include <qregexp.h>
#include <qmap.h>
#include <qeventloop.h>

#include "xchmfile.h"
#include "kchmconfig.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"

#include "bitfiddle.h"

// Big-enough buffer size for use with various routines.
#define BUF_SIZE 4096


static QMap<QString, QString>	entityDecodeMap;

// A little helper to show wait cursor
#include <qcursor.h>
#include <qapplication.h>

class KCHMShowWaitCursor
{
public:
	KCHMShowWaitCursor () { QApplication::setOverrideCursor( QCursor(Qt::WaitCursor) ); }
	~KCHMShowWaitCursor () { QApplication::restoreOverrideCursor(); }
};

//FIXME: this should be VERY slow...
inline QString CHMFile::decodeHTMLUnicodeEntity (QString& source)
{
	// Set up entityDecodeMap characters according to current textCodec
	if ( entityDecodeMap.isEmpty() )
	{
		entityDecodeMap["AElig"]	= encodeWithCurrentCodec ("\306"); // capital AE diphthong (ligature)
		entityDecodeMap["Aacute"]	= encodeWithCurrentCodec ("\301"); // capital A, acute accent
		entityDecodeMap["Acirc"]	= encodeWithCurrentCodec ("\302"); // capital A, circumflex accent
		entityDecodeMap["Agrave"]	= encodeWithCurrentCodec ("\300"); // capital A, grave accent
		entityDecodeMap["Aring"]	= encodeWithCurrentCodec ("\305"); // capital A, ring
		entityDecodeMap["Atilde"]	= encodeWithCurrentCodec ("\303"); // capital A, tilde
		entityDecodeMap["Auml"]		= encodeWithCurrentCodec ("\304"); // capital A, dieresis or umlaut mark
		entityDecodeMap["Ccedil"]	= encodeWithCurrentCodec ("\307"); // capital C, cedilla
		entityDecodeMap["Dstrok"]	= encodeWithCurrentCodec ("\320"); // whatever
		entityDecodeMap["ETH"]		= encodeWithCurrentCodec ("\320"); // capital Eth, Icelandic
		entityDecodeMap["Eacute"]	= encodeWithCurrentCodec ("\311"); // capital E, acute accent
		entityDecodeMap["Ecirc"]	= encodeWithCurrentCodec ("\312"); // capital E, circumflex accent
		entityDecodeMap["Egrave"]	= encodeWithCurrentCodec ("\310"); // capital E, grave accent
		entityDecodeMap["Euml"]		= encodeWithCurrentCodec ("\313"); // capital E, dieresis or umlaut mark
		entityDecodeMap["Iacute"]	= encodeWithCurrentCodec ("\315"); // capital I, acute accent
		entityDecodeMap["Icirc"]	= encodeWithCurrentCodec ("\316"); // capital I, circumflex accent
		entityDecodeMap["Igrave"]	= encodeWithCurrentCodec ("\314"); // capital I, grave accent
		entityDecodeMap["Iuml"]		= encodeWithCurrentCodec ("\317"); // capital I, dieresis or umlaut mark
		entityDecodeMap["Ntilde"]	= encodeWithCurrentCodec ("\321"); // capital N, tilde
		entityDecodeMap["Oacute"]	= encodeWithCurrentCodec ("\323"); // capital O, acute accent
		entityDecodeMap["Ocirc"]	= encodeWithCurrentCodec ("\324"); // capital O, circumflex accent
		entityDecodeMap["Ograve"]	= encodeWithCurrentCodec ("\322"); // capital O, grave accent
		entityDecodeMap["Oslash"]	= encodeWithCurrentCodec ("\330"); // capital O, slash
		entityDecodeMap["Otilde"]	= encodeWithCurrentCodec ("\325"); // capital O, tilde
		entityDecodeMap["Ouml"]		= encodeWithCurrentCodec ("\326"); // capital O, dieresis or umlaut mark
		entityDecodeMap["THORN"]	= encodeWithCurrentCodec ("\336"); // capital THORN, Icelandic
		entityDecodeMap["Uacute"]	= encodeWithCurrentCodec ("\332"); // capital U, acute accent
		entityDecodeMap["Ucirc"]	= encodeWithCurrentCodec ("\333"); // capital U, circumflex accent
		entityDecodeMap["Ugrave"]	= encodeWithCurrentCodec ("\331"); // capital U, grave accent
		entityDecodeMap["Uuml"]		= encodeWithCurrentCodec ("\334"); // capital U, dieresis or umlaut mark
		entityDecodeMap["Yacute"]	= encodeWithCurrentCodec ("\335"); // capital Y, acute accent
		
		entityDecodeMap["aacute"]	= encodeWithCurrentCodec ("\341"); // small a, acute accent
		entityDecodeMap["acirc"]	= encodeWithCurrentCodec ("\342"); // small a, circumflex accent
		entityDecodeMap["aelig"]	= encodeWithCurrentCodec ("\346"); // small ae diphthong (ligature)
		entityDecodeMap["agrave"]	= encodeWithCurrentCodec ("\340"); // small a, grave accent
		entityDecodeMap["aring"]	= encodeWithCurrentCodec ("\345"); // small a, ring
		entityDecodeMap["atilde"]	= encodeWithCurrentCodec ("\343"); // small a, tilde
		entityDecodeMap["auml"]		= encodeWithCurrentCodec ("\344"); // small a, dieresis or umlaut mark
		entityDecodeMap["ccedil"]	= encodeWithCurrentCodec ("\347"); // small c, cedilla
		entityDecodeMap["eacute"]	= encodeWithCurrentCodec ("\351"); // small e, acute accent
		entityDecodeMap["ecirc"]	= encodeWithCurrentCodec ("\352"); // small e, circumflex accent
		entityDecodeMap["egrave"]	= encodeWithCurrentCodec ("\350"); // small e, grave accent
		entityDecodeMap["eth"]		= encodeWithCurrentCodec ("\360"); // small eth, Icelandic
		entityDecodeMap["euml"]		= encodeWithCurrentCodec ("\353"); // small e, dieresis or umlaut mark
		entityDecodeMap["iacute"]	= encodeWithCurrentCodec ("\355"); // small i, acute accent
		entityDecodeMap["icirc"]	= encodeWithCurrentCodec ("\356"); // small i, circumflex accent
		entityDecodeMap["igrave"]	= encodeWithCurrentCodec ("\354"); // small i, grave accent
		entityDecodeMap["iuml"]		= encodeWithCurrentCodec ("\357"); // small i, dieresis or umlaut mark
		entityDecodeMap["ntilde"]	= encodeWithCurrentCodec ("\361"); // small n, tilde
		entityDecodeMap["oacute"]	= encodeWithCurrentCodec ("\363"); // small o, acute accent
		entityDecodeMap["ocirc"]	= encodeWithCurrentCodec ("\364"); // small o, circumflex accent
		entityDecodeMap["ograve"]	= encodeWithCurrentCodec ("\362"); // small o, grave accent
		entityDecodeMap["oslash"]	= encodeWithCurrentCodec ("\370"); // small o, slash
		entityDecodeMap["otilde"]	= encodeWithCurrentCodec ("\365"); // small o, tilde
		entityDecodeMap["ouml"]		= encodeWithCurrentCodec ("\366"); // small o, dieresis or umlaut mark
		entityDecodeMap["szlig"]	= encodeWithCurrentCodec ("\337"); // small sharp s, German (sz ligature)
		entityDecodeMap["thorn"]	= encodeWithCurrentCodec ("\376"); // small thorn, Icelandic
		entityDecodeMap["uacute"]	= encodeWithCurrentCodec ("\372"); // small u, acute accent
		entityDecodeMap["ucirc"]	= encodeWithCurrentCodec ("\373"); // small u, circumflex accent
		entityDecodeMap["ugrave"]	= encodeWithCurrentCodec ("\371"); // small u, grave accent
		entityDecodeMap["uuml"]		= encodeWithCurrentCodec ("\374"); // small u, dieresis or umlaut mark
		entityDecodeMap["yacute"]	= encodeWithCurrentCodec ("\375"); // small y, acute accent
		entityDecodeMap["yuml"]		= encodeWithCurrentCodec ("\377"); // small y, dieresis or umlaut mark

		entityDecodeMap["iexcl"]	= encodeWithCurrentCodec ("\241");
		entityDecodeMap["cent"]		= encodeWithCurrentCodec ("\242");
		entityDecodeMap["pound"]	= encodeWithCurrentCodec ("\243");
		entityDecodeMap["curren"]	= encodeWithCurrentCodec ("\244");
		entityDecodeMap["yen"]		= encodeWithCurrentCodec ("\245");
		entityDecodeMap["brvbar"]	= encodeWithCurrentCodec ("\246");
		entityDecodeMap["sect"]		= encodeWithCurrentCodec ("\247");
		entityDecodeMap["uml"]		= encodeWithCurrentCodec ("\250");
		entityDecodeMap["ordf"]		= encodeWithCurrentCodec ("\252");
		entityDecodeMap["laquo"]	= encodeWithCurrentCodec ("\253");
		entityDecodeMap["not"]		= encodeWithCurrentCodec ("\254");
		entityDecodeMap["shy"]		= encodeWithCurrentCodec ("\255");
		entityDecodeMap["macr"]		= encodeWithCurrentCodec ("\257");
		entityDecodeMap["deg"]		= encodeWithCurrentCodec ("\260");
		entityDecodeMap["plusmn"]	= encodeWithCurrentCodec ("\261");
		entityDecodeMap["sup1"]		= encodeWithCurrentCodec ("\271");
		entityDecodeMap["sup2"]		= encodeWithCurrentCodec ("\262");
		entityDecodeMap["sup3"]		= encodeWithCurrentCodec ("\263");
		entityDecodeMap["acute"]	= encodeWithCurrentCodec ("\264");
		entityDecodeMap["micro"]	= encodeWithCurrentCodec ("\265");
		entityDecodeMap["para"]		= encodeWithCurrentCodec ("\266");
		entityDecodeMap["middot"]	= encodeWithCurrentCodec ("\267");
		entityDecodeMap["cedil"]	= encodeWithCurrentCodec ("\270");
		entityDecodeMap["ordm"]		= encodeWithCurrentCodec ("\272");
		entityDecodeMap["raquo"]	= encodeWithCurrentCodec ("\273");
		entityDecodeMap["frac14"]	= encodeWithCurrentCodec ("\274");
		entityDecodeMap["frac12"]	= encodeWithCurrentCodec ("\275");
		entityDecodeMap["frac34"]	= encodeWithCurrentCodec ("\276");
		entityDecodeMap["iquest"]	= encodeWithCurrentCodec ("\277");
		entityDecodeMap["times"]	= encodeWithCurrentCodec ("\327");
		entityDecodeMap["divide"]	= encodeWithCurrentCodec ("\367");

 		entityDecodeMap["copy"]		= encodeWithCurrentCodec ("\251"); // copyright sign
		entityDecodeMap["reg"]		= encodeWithCurrentCodec ("\256"); // registered sign
		entityDecodeMap["nbsp"]		= encodeWithCurrentCodec ("\240"); // non breaking space

		entityDecodeMap["rsquo"]	= QChar((unsigned short) 8217);
		entityDecodeMap["trade"]    = QChar((unsigned short) 8482);
		entityDecodeMap["ldquo"]    = QChar((unsigned short) 8220);
		entityDecodeMap["mdash"]    = QChar((unsigned short) 8212);
				
		entityDecodeMap["amp"]	= "&";	// ampersand
		entityDecodeMap["gt"] = ">";	// greater than
		entityDecodeMap["lt"] = "<"; 	// less than
		entityDecodeMap["quot"] = "\""; // double quote
		entityDecodeMap["apos"] = "'"; 	// single quote
	}
	
	QRegExp r ("&(\\w+);");
	
	while ( r.search (source) != -1 )
	{
		QString ent = r.cap(1);
		if ( entityDecodeMap.find (ent) == entityDecodeMap.end() )
		{
			qWarning ("CHMFile::DecodeHTMLUnicodeEntity: could not decode HTML entity '%s', abort decoding.", ent.ascii());
			break;
		}
		
		QString before = "&" + ent + ";";
		source.replace (before, entityDecodeMap[ent]);
	}
	
	return source;
}


CHMFile::CHMFile()
	: m_chmFile(NULL), m_home("/")
{
	m_textCodec = 0;
	m_currentEncoding = 0;
	m_detectedLCID = 0;
}


CHMFile::CHMFile(const QString& archiveName)
	: m_chmFile(NULL), m_home("/")
{
	LoadCHM(archiveName);
}


CHMFile::~CHMFile()
{
	CloseCHM();
}


bool CHMFile::LoadCHM(const QString&  archiveName)
{
	chmUnitInfo ui;
	
	if(m_chmFile)
		CloseCHM();

	m_chmFile = chm_open (archiveName.ascii());
	
	if(m_chmFile == NULL)
		return false;

	m_filename = archiveName;
	
	// Every CHM has its own encoding
	m_textCodec = 0;
	m_currentEncoding = 0;
	
	InfoFromWindows();
	InfoFromSystem();

	guessTextEncoding();
	
	if ( !ResolveObject ("/$FIftiMain", &ui)
	|| !ResolveObject("/#TOPICS", &ui)
	|| !ResolveObject("/#STRINGS", &ui)
	|| !ResolveObject("/#URLTBL", &ui)
	|| !ResolveObject("/#URLSTR", &ui) )
		m_searchAvailable = false;
	else
		m_searchAvailable = true;
	
	return true;
}



void CHMFile::CloseCHM()
{
	if ( m_chmFile == NULL )
		return;

	chm_close(m_chmFile);
	
	m_chmFile = NULL;
	m_home = "/";
	m_filename = m_home = m_topicsFile = m_indexFile = m_font = QString::null;
	
	m_treeUrlMap.clear();
	entityDecodeMap.clear();
	m_textCodec = 0;
	m_detectedLCID = 0;
	m_currentEncoding = 0;

	for ( chm_loaded_files_t::iterator it = m_chmLoadedFiles.begin(); it != m_chmLoadedFiles.end(); it++ )
		delete it.data();
}

/*
 * FIXME: <OBJECT type="text/sitemap"><param name="Merge" value="hhaxref.chm::/HHOCX_c.hhc"></OBJECT>
 *  (from htmlhelp.chm)
 */
//TODO: binary TOC parser
bool CHMFile::ParseHhcAndFillTree (const QString& file, QListView *tree, bool asIndex)
{
	chmUnitInfo ui;
	const int MAX_NEST_DEPTH = 256;

	if(file.isEmpty() || !ResolveObject(file, &ui))
		return false;

	QString src;
	GetFileContentAsString(src, &ui);

	if(src.isEmpty())
		return false;

	QRegExp pairregex ( "param\\s+name\\s*=\\s*[\"'](.+)[\"']\\s+value\\s*=\\s*[\"'](.+)[\"'][^\"']*" );
	pairregex.setMinimal (TRUE);

	int pos = 0, indent = 0;
	bool in_object = false, root_created = false;
	QString url, name;
	KCHMMainTreeViewItem * rootentry[MAX_NEST_DEPTH];
	KCHMMainTreeViewItem * lastchild[MAX_NEST_DEPTH];
	
	memset (lastchild, 0, sizeof(*lastchild));
	memset (rootentry, 0, sizeof(*rootentry));
	
	// Split the HHC file by HTML tags
	int stringlen = src.length();
	
	while ( pos < stringlen 
	&& (pos = src.find ('<', pos)) != -1 )
	{
		int i, word_end = 0;
		bool in_quotes = false, in_apostrofes = false;
		
		for ( i = ++pos; i < stringlen; i++ )
		{
			if ( src[i] == '"' && !in_apostrofes )
				in_quotes = !in_quotes;
			else if ( src[i] == '\'' && !in_quotes )
				in_apostrofes = !in_apostrofes;
			else if ( src[i] == '>' && !in_quotes && !in_apostrofes )
				break;
			else if ( !src[i].isLetterOrNumber() && src[i] != '/' && !word_end )
				word_end = i;
		}
		
		QString tagword, tag = src.mid (pos, i - pos);
		 
		if ( word_end )
			tagword = src.mid (pos, word_end - pos).lower();
		else
			tagword = tag.lower();

//		qDebug ("tag: '%s', tagword: '%s'\n", tag.ascii(), tagword.ascii());
						
		// <OBJECT type="text/sitemap"> - a topic entry
		if ( tagword == "object" && tag.find ("text/sitemap", 0, false) != -1 )
			in_object = true;
		else if ( tagword == "/object" && in_object ) 
		{
			// a topic entry closed. Add a tree item
			if ( name )
			{
				KCHMMainTreeViewItem * item;

				if ( !root_created )
					indent = 0;

				// Should we add rootlevel?
				if ( !indent || asIndex )
				{
					item = new KCHMMainTreeViewItem (tree, lastchild[indent], name, url, asIndex);
				}
				else
				{
					if ( !rootentry[indent-1] )
						qFatal("CHMFile::ParseAndFillTopicsTree: child entry %d with no root entry!", indent-1);
						
					item = new KCHMMainTreeViewItem (rootentry[indent-1], lastchild[indent], name, url,  false);
				}
				
				if ( indent == 0 || !rootentry[indent] )
				{
					rootentry[indent] = item;
					root_created = true;
				}
				
				lastchild[indent] = item;
				
				if ( !asIndex )
					m_treeUrlMap[url] = item;
			}
			else
			{
				if ( !url.isEmpty() )
					qDebug ("CHMFile::ParseAndFillTopicsTree: <object> tag with url \"%s\" is parsed, but name is empty.", url.ascii());
				else
					qDebug ("CHMFile::ParseAndFillTopicsTree: <object> tag is parsed, but both name and url are empty.");	
			}

			name = url = QString::null;
			in_object = false;
			
		}
		else if ( tagword == "param" && in_object )
		{
			// we're interested in 3 types of tags:
			// <param name="Name" value="First Page">
			// <param name="Local" value="doc/uk.htm">
			if ( pairregex.search (tag) == -1 )
				qFatal ("Bad <PARAM> tag: %s", tag.ascii());
				
			QString pname = pairregex.cap(1).lower();
			QString pvalue = pairregex.cap(2);
			if ( pname == "name" )
				name = decodeHTMLUnicodeEntity (pvalue);
			else if ( pname == "local" )
				url = KCHMViewWindow::makeURLabsoluteIfNeeded (pvalue);
		}
		else if ( tagword == "ul" ) // increase indent level
		{
			// Fix for buggy help files		
			if ( ++indent >= MAX_NEST_DEPTH )
				qFatal("CHMFile::ParseAndFillTopicsTree: max nest depth (%d) is reached, error in help file", MAX_NEST_DEPTH);
				
			lastchild[indent] = 0;
			rootentry[indent] = 0;
		}
		else if ( tagword == "/ul" ) // decrease indent level
		{
			if ( --indent < 0 )
				indent = 0;
				
			rootentry[indent] = 0;
		}

		pos = i;	
	}
	
	return true;
}

bool CHMFile::ParseAndFillTopicsTree(QListView *tree)
{
	KCHMShowWaitCursor wc;
	return ParseHhcAndFillTree (m_topicsFile, tree, false);
}


bool CHMFile::ParseAndFillIndex(QListView *indexlist)
{
	KCHMShowWaitCursor wc;
	return ParseHhcAndFillTree (m_indexFile, indexlist, true);
}

bool CHMFile::IndexSearch(const QString& text, bool wholeWords, bool titlesOnly, KCHMSearchBackend::searchResults& results, unsigned int maxresults)
{
	chmUnitInfo ui, uitopics, uiurltbl, uistrings, uiurlstr;
	bool partial = false;

	if ( text.isEmpty() )
		return false;

	if ( !ResolveObject ("/$FIftiMain", &ui)
	|| !ResolveObject("/#TOPICS", &uitopics)
	|| !ResolveObject("/#STRINGS", &uistrings)
	|| !ResolveObject("/#URLTBL", &uiurltbl)
	|| !ResolveObject("/#URLSTR", &uiurlstr) )
		return false;

#define FTS_HEADER_LEN 0x32
	unsigned char header[FTS_HEADER_LEN];

	if ( RetrieveObject (&ui, header, 0, FTS_HEADER_LEN) == 0 )
		return false;
	
	unsigned char doc_index_s = header[0x1E], doc_index_r = header[0x1F];
	unsigned char code_count_s = header[0x20], code_count_r = header[0x21];
	unsigned char loc_codes_s = header[0x22], loc_codes_r = header[0x23];

	if(doc_index_s != 2 || code_count_s != 2 || loc_codes_s != 2)
	{
		// Don't know how to use values other than 2 yet. Maybe next chmspec.
		return false;
	}

	unsigned char* cursor32 = header + 0x14;
	u_int32_t node_offset = UINT32ARRAY(cursor32);

	cursor32 = header + 0x2e;
	u_int32_t node_len = UINT32ARRAY(cursor32);

	unsigned char* cursor16 = header + 0x18;
	u_int16_t tree_depth = UINT16ARRAY(cursor16);

	unsigned char word_len, pos;
	QString word;
	u_int32_t i = sizeof(u_int16_t);
	u_int16_t free_space;

	QMemArray<unsigned char> buffer(node_len);

	node_offset = GetLeafNodeOffset (text, node_offset, node_len, tree_depth, &ui);

	if ( !node_offset )
		return false;

	do
	{
		// got a leaf node here.
		if ( RetrieveObject (&ui, buffer.data(), node_offset, node_len) == 0 )
			return false;

		cursor16 = buffer.data() + 6;
		free_space = UINT16ARRAY(cursor16);

		i = sizeof(u_int32_t) + sizeof(u_int16_t) + sizeof(u_int16_t);
		u_int64_t wlc_count, wlc_size;
		u_int32_t wlc_offset;

		while (i < node_len - free_space)
		{
			word_len = *(buffer.data() + i);
			pos = *(buffer.data() + i + 1);

			char *wrd_buf = new char[word_len];
			memcpy (wrd_buf, buffer.data() + i + 2, word_len - 1);
			wrd_buf[word_len - 1] = 0;

			if(pos == 0)
				word = encodeWithCurrentCodec (wrd_buf);
			else
				word = word.mid (0, pos) + encodeWithCurrentCodec (wrd_buf);

			delete[] wrd_buf;

			i += 2 + word_len;
			unsigned char title = *(buffer.data() + i - 1);

			size_t encsz;
			wlc_count = be_encint (buffer.data() + i, encsz);
			i += encsz;
		
			cursor32 = buffer.data() + i;
			wlc_offset = UINT32ARRAY(cursor32);

			i += sizeof(u_int32_t) + sizeof(u_int16_t);
			wlc_size =  be_encint (buffer.data() + i, encsz);
			i += encsz;

			cursor32 = buffer.data();
			node_offset = UINT32ARRAY(cursor32);
		
			if ( !title && titlesOnly )
				continue;

			if ( wholeWords && text.lower() == word.lower() )
				return ProcessWLC(wlc_count, wlc_size, 
						  wlc_offset, doc_index_s, 
						  doc_index_r,code_count_s, 
						  code_count_r, loc_codes_s, 
						  loc_codes_r, &ui, &uiurltbl,
						  &uistrings, &uitopics,
						  &uiurlstr, results, maxresults);

			if ( !wholeWords )
			{
				if ( word.startsWith (text))
				{
					partial = true;
					
					ProcessWLC(wlc_count, wlc_size, 
						   wlc_offset, doc_index_s, 
						   doc_index_r,code_count_s, 
						   code_count_r, loc_codes_s, 
						   loc_codes_r, &ui, &uiurltbl,
						   &uistrings, &uitopics,
						   &uiurlstr, results, maxresults);

				}
				else if ( QString::compare (text.lower(), word.mid(0, text.length())) < -1 )
					break;
			}

			if ( results.size() >= maxresults )
				break;
		}	
	}
	while ( !wholeWords && word.startsWith (text) && node_offset );
	
	return partial;
}


bool CHMFile::ResolveObject(const QString& fileName, chmUnitInfo *ui)
{
	return m_chmFile != NULL 
	&& ::chm_resolve_object(m_chmFile, fileName.ascii(), ui) ==
CHM_RESOLVE_SUCCESS;
}


size_t CHMFile::RetrieveObject(chmUnitInfo *ui, unsigned char *buffer,
							   off_t fileOffset, size_t bufferSize)
{
	return ::chm_retrieve_object(m_chmFile, ui, buffer, fileOffset,
								 bufferSize);
}


inline u_int32_t CHMFile::GetLeafNodeOffset(const QString& text,
											 u_int32_t initialOffset,
											 u_int32_t buffSize,
											 u_int16_t treeDepth,
											 chmUnitInfo *ui)
{
	u_int32_t test_offset = 0;
	unsigned char* cursor16, *cursor32;
	unsigned char word_len, pos;
	u_int32_t i = sizeof(u_int16_t);
	QMemArray<unsigned char> buffer(buffSize);
	QString word;
	
	while(--treeDepth)
	{
		if ( initialOffset == test_offset )
			return 0;

		test_offset = initialOffset;
		if ( RetrieveObject (ui, buffer.data(), initialOffset, buffSize) == 0 )
			return 0;

		cursor16 = buffer.data();
		u_int16_t free_space = UINT16ARRAY(cursor16);

		while (i < buffSize - free_space )
		{
			word_len = *(buffer.data() + i);
			pos = *(buffer.data() + i + 1);

			char *wrd_buf = new char[word_len];
			memcpy ( wrd_buf, buffer.data() + i + 2, word_len - 1 );
			wrd_buf[word_len - 1] = 0;

			if ( pos == 0 )
				word = encodeWithCurrentCodec (wrd_buf);
			else
				word = word.mid(0, pos) + encodeWithCurrentCodec (wrd_buf);

			delete[] wrd_buf;

			if ( text.lower() <= word.lower() )
			{
				cursor32 = buffer.data() + i + word_len + 1;
				initialOffset = UINT32ARRAY(cursor32);
				break;
			}

			i += word_len + sizeof(unsigned char) +
				sizeof(u_int32_t) + sizeof(u_int16_t);
		}
	}

	if ( initialOffset == test_offset )
		return 0;

	return initialOffset;
}


inline bool CHMFile::ProcessWLC(u_int64_t wlc_count, u_int64_t wlc_size,
								u_int32_t wlc_offset, unsigned char ds,
								unsigned char dr, unsigned char cs,
								unsigned char cr, unsigned char ls,
								unsigned char lr, chmUnitInfo *uimain,
								chmUnitInfo* uitbl, chmUnitInfo *uistrings,
								chmUnitInfo* topics, chmUnitInfo *urlstr,
								KCHMSearchBackend::searchResults& results,
								unsigned int maxresults)
{
	int wlc_bit = 7;
	u_int64_t index = 0, count;
	size_t length, off = 0;
	QMemArray<unsigned char> buffer (wlc_size);
	unsigned char *cursor32;
	u_int32_t stroff, urloff;

#define TOPICS_ENTRY_LEN 16
	unsigned char entry[TOPICS_ENTRY_LEN];

#define COMMON_BUF_LEN 1025
	unsigned char combuf[COMMON_BUF_LEN];

	if ( RetrieveObject (uimain, buffer.data(), wlc_offset, wlc_size) == 0 )
		return false;

	for ( u_int64_t i = 0; i < wlc_count; ++i )
	{
		if ( wlc_bit != 7 )
		{
			++off;
			wlc_bit = 7;
		}

		index += sr_int (buffer.data() + off, &wlc_bit, ds, dr, length);
		off += length;

		if ( RetrieveObject (topics, entry, index * 16, TOPICS_ENTRY_LEN) == 0 )
			return false;

		cursor32 = entry + 4;
		combuf[COMMON_BUF_LEN - 1] = 0;
		stroff = UINT32ARRAY(cursor32);

		QString topic;

		if ( RetrieveObject (uistrings, combuf, stroff, COMMON_BUF_LEN - 1) == 0 )
			topic = "Untitled in index";
		else
		{
			combuf[COMMON_BUF_LEN - 1] = 0;
			topic = encodeWithCurrentCodec ((const char*)combuf);
		}
	      
		cursor32 = entry + 8;
		urloff = UINT32ARRAY(cursor32);

		if ( RetrieveObject (uitbl, combuf, urloff, 12) == 0 )
			return false;

		cursor32 = combuf + 8;
		urloff = UINT32ARRAY (cursor32);

		if ( RetrieveObject (urlstr, combuf, urloff + 8, COMMON_BUF_LEN - 1) == 0 )
			return false;
	       
		combuf[COMMON_BUF_LEN - 1] = 0;

		QString url = encodeWithCurrentCodec ((const char*) combuf);

		if ( !url.isEmpty() && !topic.isEmpty() )
		{
			if ( results.size() >= maxresults )
				return true;
				
			results.push_back (KCHMSearchBackend::SearchResult (0, topic, url));
		}

		count = sr_int (buffer.data() + off, &wlc_bit, cs, cr, length);
		off += length;

		for (u_int64_t j = 0; j < count; ++j)
		{
			u_int64_t lcode = sr_int (buffer.data() + off, &wlc_bit, ls, lr, length);
			off += length;
printf ("Location code: %d\n", (int) lcode);
		}
	}

	return true;
}


inline bool CHMFile::InfoFromWindows()
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

		u_int32_t entries = *(u_int32_t *)(buffer);
		FIXENDIAN32(entries);
		u_int32_t entry_size = *(u_int32_t *)(buffer + 0x04);
		FIXENDIAN32(entry_size);
		
		QByteArray uptr(entries * entry_size);
		unsigned char* raw = (unsigned char*) uptr.data();
		
		if ( !RetrieveObject (&ui, raw, 8, entries * entry_size) )
			return false;

		if( !ResolveObject ("/#STRINGS", &ui) )
			return false;

		for ( u_int32_t i = 0; i < entries; ++i )
		{
			u_int32_t offset = i * entry_size;
			
			u_int32_t off_title = *(u_int32_t *)(raw + offset + 0x14);
			FIXENDIAN32(off_title);

			u_int32_t off_home = *(u_int32_t *)(raw + offset + 0x68);
			FIXENDIAN32(off_home);

			u_int32_t off_hhc = *(u_int32_t *)(raw + offset + 0x60);
			FIXENDIAN32(off_hhc);
			
			u_int32_t off_hhk = *(u_int32_t *)(raw + offset + 0x64);
			FIXENDIAN32(off_hhk);

			factor = off_title / 4096;

			if ( size == 0 ) 
				size = RetrieveObject(&ui, buffer, factor * 4096, BUF_SIZE);

			if ( size && off_title )
				m_title = QString ((const char*) (buffer + off_title % 4096));

			if ( factor != off_home / 4096)
			{
				factor = off_home / 4096;		
				size = RetrieveObject (&ui, buffer, factor * 4096, BUF_SIZE);
			}
			
			if ( size && off_home )
				m_home = QString("/") + QString( (const char*) buffer + off_home % 4096);

			if ( factor != off_hhc / 4096)
			{
				factor = off_hhc / 4096;
				size = RetrieveObject(&ui, buffer, factor * 4096, BUF_SIZE);
			}
		
			if ( size && off_hhc )
				m_topicsFile = QString("/") + QString ((const char*) buffer + off_hhc % 4096);

			if ( factor != off_hhk / 4096)
			{
				factor = off_hhk / 4096;
				size = RetrieveObject (&ui, buffer, factor * 4096, BUF_SIZE);
			}

			if ( size && off_hhk )
				m_indexFile = QString("/") + QString((const char*) buffer + off_hhk % 4096);
		}
	}
	return true;
}



inline bool CHMFile::InfoFromSystem()
{
	unsigned char buffer[BUF_SIZE];
	chmUnitInfo ui;
	
	int index = 0;
	unsigned char* cursor = NULL;
	u_int16_t value = 0;

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
	for ( index = 0; index < (size - 1 - (long)sizeof(u_int16_t)) ;)
	{
		cursor = buffer + index;
		value = UINT16ARRAY(cursor);

		switch(value)
		{
		case 0:
			index += 2;
			cursor = buffer + index;
			
			if(m_topicsFile.isEmpty())
				m_topicsFile = QString("/") + QString((const char*) buffer + index + 2);
				
			break;
			
		case 1:
			index += 2;
			cursor = buffer + index;

			if(m_indexFile.isEmpty())
				m_indexFile = QString("/") + QString ((const char*)buffer + index + 2);
			break;
		
		case 2:
			index += 2;
			cursor = buffer + index;
				
			if(m_home.isEmpty() || m_home == "/")
				m_home = QString("/") + QString ((const char*) buffer + index + 2);
			break;
			
		case 3:
			index += 2;
			cursor = buffer + index;
			m_title = QString((const char*) (buffer + index + 2));
			break;

		case 4:
			index += 2;
			cursor = buffer + index;

			m_detectedLCID = (short) *((unsigned int*) (buffer + index + 2));
			break;

		case 6:
			index += 2;
			cursor = buffer + index;

			if(m_topicsFile.isEmpty()) {
				QString topicAttempt = "/", tmp;
				topicAttempt += QString ((const char*) buffer +index +2);

				tmp = topicAttempt + ".hhc";
				
				if ( ResolveObject (tmp.ascii(), &ui) )
					m_topicsFile = tmp;

				tmp = topicAttempt + ".hhk";
				
				if ( ResolveObject(tmp.ascii(), &ui) )
					m_indexFile = tmp;
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

 
KCHMMainTreeViewItem * CHMFile::getTreeItem( const QString & str )
{
	CHMTreeUrlMap::iterator it = m_treeUrlMap.find (str);
	if ( it == m_treeUrlMap.end() )
		return 0;
		
	return *it;
}


bool CHMFile::guessTextEncoding( )
{
	const KCHMTextEncoding::text_encoding_t * enc = 0;

/*
 * Skip encoding by font family; detect encoding by LCID seems to be more reliable
	// First try 'by font'
	int i, charset;
		
	if ( !m_font.isEmpty() )
	{
		if ( (i = m_font.findRev (',')) != -1
		&& (charset = m_font.mid (i+1).toUInt()) != 0 )
			enc = KCHMTextEncoding::lookupByWinCharset(charset);
	}

	// The next step - detect by LCID
	if ( !enc && m_detectedLCID )
		enc = KCHMTextEncoding::lookupByLCID (m_detectedLCID);
*/

	if ( !m_detectedLCID
	|| (enc = KCHMTextEncoding::lookupByLCID (m_detectedLCID)) == 0 )
		qFatal ("Could not detect text encoding by LCID");
	
	if ( changeFileEncoding (enc->qtcodec) )
	{
		m_currentEncoding = enc;
		mainWindow->showInStatusBar (QString("Detected help file charset: ") +  enc->charset);
		return true;
	}
	
	return false;
}

bool CHMFile::changeFileEncoding( const char * qtencoding )
{
	// Set up encoding
	m_textCodec = QTextCodec::codecForName (qtencoding);
	
	if ( !m_textCodec )
	{
		qWarning ("Could not set up Text Codec for encoding '%s'", qtencoding);
		return false;
	}
	
	entityDecodeMap.clear();
	return true;
}


bool CHMFile::setCurrentEncoding( const KCHMTextEncoding::text_encoding_t * enc )
{
	m_currentEncoding = enc;
	return changeFileEncoding (enc->qtcodec);
}


bool CHMFile::GetFileContentAsString(QString& str, chmUnitInfo *ui)
{
	QByteArray buf (ui->length);
			
	if ( RetrieveObject (ui, (unsigned char*) buf.data(), 0, ui->length) )
	{
		str = encodeWithCurrentCodec((const char*) buf);
		return true;
	}
	else
	{
		str = QString::null;
		return false;
	}
}


bool CHMFile::GetFileContentAsString( QString & str, QString filename, QString location )
{
	str = QString::null;

	if ( m_filename == filename )
		return GetFileContentAsString (str, location);

	// Load a file if it is not already loaded
	CHMFile * file = getCHMfilePointer (filename);

	if ( !file )
		return false;

	return file->GetFileContentAsString (str, location);
}


bool CHMFile::GetFileContentAsString (QString& str, QString location)
{
	chmUnitInfo ui;

	if( !ResolveObject(location, &ui) )
		return false;
		
	return GetFileContentAsString(str, &ui);
}


CHMFile * CHMFile::getCHMfilePointer( const QString & filename )
{
	if ( m_filename == filename )
		return this;

	// Load a file if it is not already loaded
	if ( m_chmLoadedFiles.find (filename) == m_chmLoadedFiles.end() )
	{
		CHMFile * newfile = new CHMFile;

		if ( !newfile->LoadCHM (filename) )
		{
			delete newfile;
			return 0;
		}

		m_chmLoadedFiles[filename] = newfile;
	}

	return m_chmLoadedFiles[filename];
}


static int chm_enumerator_callback (struct chmFile*, struct chmUnitInfo *ui, void *context)
{
	((QValueVector<QString> *) context)->push_back (ui->path);
    return CHM_ENUMERATOR_CONTINUE;
}

bool CHMFile::enumerateArchive( QValueVector< QString > & files )
{
	files.clear();
	return chm_enumerate (m_chmFile, CHM_ENUMERATE_ALL, chm_enumerator_callback, &files);
}

