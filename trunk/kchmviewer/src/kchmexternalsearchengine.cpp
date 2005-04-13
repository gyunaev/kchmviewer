/***************************************************************************
 *   Copyright (C) 2005 by Georgy Yunaev                                   *
 *   tim@krasnogorsk.ru                                                    *
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

#include <qtextbrowser.h>
#include <qapplication.h>
#include <qclipboard.h>
#include <qregexp.h>

#include "kchmviewwindow.h"
#include "kchmmainwindow.h"
#include "kchmexternalsearch.h"
#include "kchmexternalsearchengine.h"


class KCHMSearchIndexBuilder
{
public:
<<<<<<< kchmexternalsearchengine.cpp
	KCHMSearchIndexBuilder ( QValueList<KCHMSearchEngineGeorge::IndexEntry>& indexmap, QMap<QString, int>& wordsmap );
=======
	KCHMSearchIndexBuilder ( QValueList<KCHMSearchEngineGeorge::IndexEntry>& map );
>>>>>>> 1.3
	~KCHMSearchIndexBuilder();
	
	bool addWordsFromPage ( const QString& url );
	void convertPages (QMap<int, QString>& map);

private:
	//! Parse a HTML page, stripping out HTML tags, and split into words everything inside the page
	void parseAndTokenizeHtmlPage ( const QString& page, QStringList& words );

	KCHMViewWindow		*	m_viewwindow;
	QClipboard 			*	m_clipboard;

	unsigned short			m_pageid;
	unsigned int			m_wordid;
	unsigned int			m_indexmapid;

	QMap<QString, int>		m_pagesmap;
<<<<<<< kchmexternalsearchengine.cpp
	QMap<QString, int>&		m_wordsmap;
	QValueList<KCHMSearchEngineGeorge::IndexEntry>&	m_indexmap;
=======
	QMap<QString, int>		m_wordsmap;
	QValueList<KCHMSearchEngineGeorge::IndexEntry>&	m_indexmap;
>>>>>>> 1.3
};


<<<<<<< kchmexternalsearchengine.cpp
KCHMSearchIndexBuilder::KCHMSearchIndexBuilder ( QValueList<KCHMSearchEngineGeorge::IndexEntry>& indexmap, QMap<QString, int>& wordsmap )
	: m_indexmap(indexmap), m_wordsmap(wordsmap)
=======
KCHMSearchIndexBuilder::KCHMSearchIndexBuilder( QValueList< KCHMSearchEngineGeorge::IndexEntry > & map )
	: m_indexmap(map)
>>>>>>> 1.3
{
	m_pageid = m_wordid = m_indexmapid = 1;
	m_viewwindow = new KCHMViewWindow (0, false);
	m_viewwindow->hide();

	m_clipboard = QApplication::clipboard();
}


KCHMSearchIndexBuilder::~ KCHMSearchIndexBuilder( )
{
	m_clipboard->clear(QClipboard::Clipboard);
	delete m_viewwindow;
}


bool KCHMSearchIndexBuilder::addWordsFromPage( const QString & url )
{

	if ( !m_viewwindow->LoadPage(url) )
		return false;

	m_viewwindow->selectAll();
	m_viewwindow->copy();
	
    // Copy text from the clipboard (paste)
	QString text = m_clipboard->text(QClipboard::Clipboard);

	text.simplifyWhiteSpace ();
	QStringList words = QStringList::split ( QRegExp ("[\\.,!'\"\\:\\;\\?\\s]"), text.lower() );

/*TODO: newest version of HTML parser
	QString page;
	QStringList words;

	if ( !::mainWindow->getChmFile()->GetFileContentAsString (page, url) )
		return false;

	parseAndTokenizeHtmlPage ( page, words );
	page = QString::null; // save some memory
*/
	if ( m_pagesmap.find (url) == m_pagesmap.end() )
		m_pagesmap[url] = m_pageid++;
	
	for ( unsigned int i = 0; i < words.size(); i++ )
	{
		// Skip one and two-letter words
		if ( words[i].length() < 3 )
			continue;

		// First, search for the word in the wordmap. If absent, add it.
		if ( m_wordsmap.find (words[i]) == m_wordsmap.end() )
			m_wordsmap[words[i]] = m_wordid++;

		// Add an index element
		m_indexmap.push_back (KCHMSearchEngineGeorge::IndexEntry (m_pagesmap[url], m_wordsmap[words[i]], i));
	}

	return true;
}


void KCHMSearchIndexBuilder::convertPages (QMap<int, QString>& map)
{
	for ( QMap<QString, int>::const_iterator it = m_pagesmap.begin(); it != m_pagesmap.end(); it++ )
		map[it.data()] = it.key();
}

/*********************************************************************************************************/

KCHMSearchEngineGeorge::KCHMSearchEngineGeorge()
{
	m_indexbuilder = 0;
}


KCHMSearchEngineGeorge::~KCHMSearchEngineGeorge()
{
	delete m_indexbuilder;
}

void KCHMSearchEngineGeorge::indexInit( )
{
	m_indexbuilder = new KCHMSearchIndexBuilder (m_indexmap, m_wordsmap);
}

bool KCHMSearchEngineGeorge::indexAddFile( const QString & url )
{
	if ( !m_indexbuilder->addWordsFromPage(url) )
	{
		qWarning ("KCHMSearchEngineGeorge::indexAddFile: Could not add file content of %s", url.ascii());
		return false;
	}

	return true;
}

void KCHMSearchEngineGeorge::indexDone( )
{
	m_indexbuilder->convertPages (m_pagesmap);

	delete m_indexbuilder;
	m_indexbuilder = 0;
}

bool KCHMSearchEngineGeorge::loadIndexFile( const QString & filename )
{
	return false;
}

bool KCHMSearchEngineGeorge::saveIndexFile( const QString & filename )
{
	return false;
}

<<<<<<< kchmexternalsearchengine.cpp
bool KCHMSearchEngineGeorge::doSearch (const QString& word, KCHMSearchEngine::searchResults& results, unsigned int limit)
=======
bool KCHMSearchEngineGeorge::doSearch (const QString& query, KCHMSearchEngine::searchResults& results, unsigned int limit)
>>>>>>> 1.3
{
<<<<<<< kchmexternalsearchengine.cpp
	// First, try to find the word index
	if ( m_wordsmap.find (word.lower()) == m_wordsmap.end() )
		return true;
	
	int wordidx = m_wordsmap[word.lower()];
	QMap<int, int> found_pages;
	QMap<int, int>::const_iterator found_pages_it;

	for ( unsigned int i = 0; i < m_indexmap.size(); i++ )
	{
		if ( m_indexmap[i].word != wordidx )
			continue;

		if ( --limit == 0 )
			break;

		found_pages[m_indexmap[i].page] = 1;
	}

	for ( found_pages_it = found_pages.begin(); found_pages_it != found_pages.end(); found_pages_it++ )
		results.push_back (m_pagesmap[found_pages_it.key()]);

	return true;
=======
	return false;
>>>>>>> 1.3
}

void KCHMSearchEngineGeorge::invalidate( )
{
	m_pagesmap.clear();
	m_wordsmap.clear();
	m_indexmap.clear();
}

bool KCHMSearchEngineGeorge::hasValidIndex( )
{
	return !m_pagesmap.isEmpty();
}
