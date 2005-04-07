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
#include "kchmsimplesearchengine.h"

KCHMSimpleSearchEngine::KCHMSimpleSearchEngine()
{
}


KCHMSimpleSearchEngine::~KCHMSimpleSearchEngine()
{
}

bool KCHMSimpleSearchEngine::addToIndex( const QString & url )
{
	SearchIndexBuild buildidx;
			
	KCHMViewWindow * wnd = new KCHMViewWindow(0);
	wnd->hide();
	
	wnd->selectAll();
	wnd->copy();
	QClipboard *cb = QApplication::clipboard();

    // Copy text from the clipboard (paste)
	QString text = cb->text(QClipboard::Clipboard);
	
	if ( buildidx.m_pagesmap.find (url) == buildidx.m_pagesmap.end() )
		buildidx.m_pagesmap[url] = buildidx.m_pageid++;
	
	addPageToIndex (buildidx.m_pagesmap[url], buildidx, text);
	
	cb->clear(QClipboard::Clipboard);
	
	// Convert build index to the usable index
	QMap< QString, int >::const_iterator it;
	
	for ( it = buildidx.m_wordsmap.begin(); it != buildidx.m_wordsmap.end(); it++ )
		m_wordsmap[it.data()] = it.key();
	
	for ( it = buildidx.m_pagesmap.begin(); it != buildidx.m_pagesmap.end(); it++ )
		m_pagesmap[it.data()] = it.key();
	
	m_indexmap = buildidx.m_indexmap;
	return true;
}


void KCHMSimpleSearchEngine::addPageToIndex( unsigned short pageurl, SearchIndexBuild & build, QString & text )
{
	text.simplifyWhiteSpace ();
	QStringList tokens = QStringList::split ( QRegExp ("[\\.,!'\"\\:\\;\\?\\s]"), text.lower() );

	for ( unsigned int i = 0; i < tokens.size(); i++ )
	{
		// First, search for the word in the wordmap. If absent, add it.
		if ( build.m_wordsmap.find (tokens[i]) == build.m_wordsmap.end() )
			build.m_wordsmap[tokens[i]] = build.m_wordid++;

		// Add an index element
		build.m_indexmap.push_back (IndexEntry (pageurl, build.m_wordsmap[tokens[i]], i));
	}
}
