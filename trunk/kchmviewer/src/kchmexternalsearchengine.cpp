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
	KCHMSearchIndexBuilder ( QValueList<KCHMExternalSearchEngine::IndexEntry>& map );
	~KCHMSearchIndexBuilder();
	
	bool addWordsFromPage ( const QString& url );
	void convertPages (QMap<int, QString>& map);
	void convertWords (QMap<int, QString>& map);

private:
	KCHMViewWindow		*	m_viewwindow;
	QClipboard 			*	m_clipboard;

	unsigned short			m_pageid;
	unsigned int			m_wordid;
	unsigned int			m_indexmapid;

	QMap<QString, int>		m_pagesmap;
	QMap<QString, int>		m_wordsmap;
	QValueList<KCHMExternalSearchEngine::IndexEntry>&	m_indexmap;
};


KCHMSearchIndexBuilder::KCHMSearchIndexBuilder( QValueList< KCHMExternalSearchEngine::IndexEntry > & map )
	: m_indexmap(map)
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

	if ( m_pagesmap.find (url) == m_pagesmap.end() )
		m_pagesmap[url] = m_pageid++;
	
	text.simplifyWhiteSpace ();
	QStringList words = QStringList::split ( QRegExp ("[\\.,!'\"\\:\\;\\?\\s]"), text.lower() );

	for ( unsigned int i = 0; i < words.size(); i++ )
	{
		// First, search for the word in the wordmap. If absent, add it.
		if ( m_wordsmap.find (words[i]) == m_wordsmap.end() )
			m_wordsmap[words[i]] = m_wordid++;

		// Add an index element
		m_indexmap.push_back (KCHMExternalSearchEngine::IndexEntry (m_pagesmap[url], m_wordsmap[words[i]], i));
	}

	return true;
}


void KCHMSearchIndexBuilder::convertPages (QMap<int, QString>& map)
{
	for ( QMap<QString, int>::const_iterator it = m_pagesmap.begin(); it != m_pagesmap.end(); it++ )
		map[it.data()] = it.key();
}

void KCHMSearchIndexBuilder::convertWords (QMap<int, QString>& map)
{
	for ( QMap<QString, int>::const_iterator it = m_wordsmap.begin(); it != m_wordsmap.end(); it++ )
		map[it.data()] = it.key();
}

/*********************************************************************************************************/

KCHMExternalSearchEngine::KCHMExternalSearchEngine()
{
	m_indexbuilder = 0;
}


KCHMExternalSearchEngine::~KCHMExternalSearchEngine()
{
	delete m_indexbuilder;
}

void KCHMExternalSearchEngine::indexInit( )
{
	m_indexbuilder = new KCHMSearchIndexBuilder (m_indexmap);
}

bool KCHMExternalSearchEngine::indexAddFile( const QString & url )
{
	if ( !m_indexbuilder->addWordsFromPage(url) )
	{
		qWarning ("KCHMExternalSearchEngine::indexAddFile: Could not add file content of %s", url.ascii());
		return false;
	}

	return true;
}

void KCHMExternalSearchEngine::indexDone( )
{
	m_indexbuilder->convertPages (m_pagesmap);
	m_indexbuilder->convertWords (m_wordsmap);

	delete m_indexbuilder;
	m_indexbuilder = 0;
}

bool KCHMExternalSearchEngine::loadIndexFile( const QString & filename )
{
}

bool KCHMExternalSearchEngine::saveIndexFile( const QString & filename )
{
}

bool KCHMExternalSearchEngine::doSearch( const QString & query, search_results_t & results )
{
}

void KCHMExternalSearchEngine::invalidate( )
{
}

