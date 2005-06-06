
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

#include <qlayout.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qstatusbar.h>
#include <qmessagebox.h>
#include <qregexp.h>

#include "kchmmainwindow.h"
#include "kchmsearchwindow.h"
#include "kchmconfig.h"
#include "xchmfile.h"

KCHMSearchWindow::KCHMSearchWindow( QWidget * parent, const char * name, WFlags f )
	: QWidget (parent, name, f)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	m_searchQuery = new QComboBox (TRUE, this);
	m_searchQuery->setFocus();
	m_searchQuery->setMaxCount (10);
	
	m_searchList = new QListView (this);
	m_searchList->addColumn( "Title" );
	m_searchList->addColumn( "Location" );
	m_searchList->setShowToolTips(true);
		
	connect( (m_searchQuery->lineEdit()), SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	connect( m_searchList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );

	m_matchSimilarWords = new QCheckBox (this);
	m_matchSimilarWords->setText (tr("Match similar words"));

	m_searchInResult = new QCheckBox (this);
	m_searchInResult->setText (tr("Search in result"));
	
	layout->addWidget (new QLabel (tr("Type in word(s) to search for:"), this));
	layout->addWidget (m_searchQuery);
	layout->addSpacing (10);
	layout->addWidget (m_searchList);
	layout->addWidget (m_matchSimilarWords);
	layout->addWidget (m_searchInResult);
}

void KCHMSearchWindow::invalidate( )
{
	m_searchList->clear();
	m_searchQuery->clear();
	m_searchQuery->lineEdit()->clear();
}

void KCHMSearchWindow::onReturnPressed( )
{
	KCHMSearchResults_t results;
	QString text = m_searchQuery->lineEdit()->text();
	
	if ( text.isEmpty() )
		return;

	// If 

	m_searchList->clear();
	
	if ( searchQuery ( text, results ) )
	{
		if ( !results.empty() )
		{
			for ( unsigned int i = 0; i < results.size(); i++ )
			{
				new KCMSearchTreeViewItem (m_searchList, results[i].title, results[i].url, results[i].url);
			}

			::mainWindow->showInStatusBar( tr("Search returned %1 results") . arg(results.size()) );
		}
		else
			::mainWindow->showInStatusBar( tr("Search returned no results") );
	}
	else
		::mainWindow->showInStatusBar( tr("Search failed") );
}

void KCHMSearchWindow::onDoubleClicked( QListViewItem *item, const QPoint &, int)
{
	if ( !item )
		return;
	
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) item;
	::mainWindow->openPage(treeitem->getUrl(), false);
}

void KCHMSearchWindow::restoreSettings( const KCHMSettings::search_saved_settings_t & settings )
{
	for ( unsigned int i = 0; i < settings.size(); i++ )
		m_searchQuery->insertItem (settings[i]);
}

void KCHMSearchWindow::saveSettings( KCHMSettings::search_saved_settings_t & settings )
{
	settings.clear();

	for ( int i = 0; i < m_searchQuery->count(); i++ )
		settings.push_back (m_searchQuery->text(i));
}


static inline void validateWord ( QString & word, bool & query_valid )
{
	QRegExp rxvalid ("[^\\d\\w_\\.]+");
	
	QString orig = word;
	word.remove ( rxvalid );
		
	if ( word != orig )
		query_valid = false;
}

static inline void validateWords ( QStringList & wordlist, bool & query_valid )
{
	QRegExp rxvalid ("[^\\d\\w_\\.]+");
	
	for ( unsigned int i = 0; i < wordlist.size(); i++ )
		validateWord ( wordlist[i], query_valid );
}


bool KCHMSearchWindow::searchQuery( QString query, KCHMSearchResults_t & searchresults, unsigned int limit_results )
{
	QStringList words_must_exist, words_must_not_exist;
	QValueVector<QStringList> phrases_must_exist;
	QStringList words_highlight;
	bool query_valid = true;
	KCHMSearchProgressResults_t results;
	int pos;
	unsigned int i;	
		
	/*
	 * Parse the search query with a simple state machine.
	 * Query should consist of one of more words separated by a space with a possible prefix.
	 * A prefix may be:
	 *   +   indicates that the word is required; any page without this word is excluded from the result.
	 *   -   indicates that the word is required to be absent; any page with this word is excluded from
	 *       the result.
	 *   "." indicates a phrase. Anything between quotes indicates a phrase, which is set of space-separated
	 *       words. Will be in result only if the words in phrase are in page in the same sequence, and
	 *       follow each other.
	 *   If there is no prefix, the word considered as required.
	 */
	
	QRegExp rxphrase( "\"(.*)\"" );
	QRegExp rxword( "([^\\s]+)" );
	rxphrase.setMinimal( TRUE );

	// First, get the phrase queries
	while ( (pos = rxphrase.search (query, 0)) != -1 )
	{
		// A phrase query found. Locate its boundaries, and parse it.
		QStringList plist = QStringList::split ( QRegExp ("\\s+"), rxphrase.cap ( 1 ));
		
		validateWords ( plist, query_valid );
		
		if ( plist.size() > 0 )
			phrases_must_exist.push_back( plist );
		
		query.remove (pos, rxphrase.matchedLength());
	}

	// Then, parse the rest query
	while ( (pos = rxword.search (query, 0)) != -1 )
	{
		// A phrase query found. Locate its boundaries, and parse it.
		QString word = rxword.cap ( 1 );
		QChar type = '+';
		
		if ( word[0] == '-' || word[0] == '+' )
		{
			type = word[0];
			word.remove (0, 1);
		}
		
		validateWord ( word, query_valid );
				
		if ( type == '-' )
			words_must_not_exist.push_back ( word );
		else
			words_must_exist.push_back ( word );
		
		query.remove (pos, rxword.matchedLength());
	}

#if defined (DUMP_SEARCH_QUERY)
	// Dump the search query
	QString qdump;
	for ( i = 0; i < phrases_must_exist.size(); i++ )
		qdump += QString(" \"") + phrases_must_exist[i].join (" ") + QString ("\"");

	for ( i = 0; i < words_must_not_exist.size(); i++ )
		qdump += QString (" -") + words_must_not_exist[i];
	
	for ( i = 0; i < words_must_exist.size(); i++ )
		qdump += QString (" +") + words_must_exist[i];

	qDebug ("Search query dump: %s", qdump.ascii());
#endif

	// First search for phrases
	if ( phrases_must_exist.size() > 0 )
	{
		for ( i = 0; i < phrases_must_exist.size(); i++ )
			if ( !searchPhrase ( phrases_must_exist[i], results ) )
				return false;
	}

	for ( i = 0; i < words_must_exist.size(); i++ )
		if ( !searchWord ( words_must_exist[i], results, TYPE_ADD ) )
			return false;
		
	for ( i = 0; i < words_must_not_exist.size(); i++ )
		searchWord ( words_must_not_exist[i], results, TYPE_REMOVE );

	return true;
}


bool KCHMSearchWindow::searchWord( const QString & word, KCHMSearchProgressResults_t & results, SearchType_t type )
{
/*	// OR is the simplest case - just fill the structure up.
	if ( type == TYPE_OR )
		return ::mainWindow->getChmFile()->SearchWord(word, true, false, results, limit_results);
	
	// For AND and PHRASE searches, we need to use temp object.
	//TODO: move all result array manipulations to the CHMFile itself
	KCHMSearchResults_t newresults;

	if ( !::mainWindow->getChmFile()->SearchWord(word, true, false, newresults, limit_results) )
		return false;

	// Only AND is supported now.
	//FIXME: this is probably the worst possible implementation.
	unsigned int i, j;
	for ( i = 0; i < results.size(); i++ )
	{
		for ( j = 0; j < newresults.size(); j++ )
			if ( results[i].title == newresults[j].title )
				break;

		if ( j == newresults.size() )
			results.erase (results.begin() + i--);
	}
*/
	return true;
}

bool KCHMSearchWindow::searchPhrase( const QStringList & phrase, KCHMSearchProgressResults_t & results )
{
	// Accumulate the phrase data here.
	KCHMSearchProgressResults_t phrasechecker;

	for ( unsigned int 

	return false;
}
