/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
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

#include "kchmsearchwindow.h"

#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "xchmfile.h"

//#define DEBUG_SEARCH(A)	qDebug A
#define DEBUG_SEARCH(A)

KCHMSearchWindow::KCHMSearchWindow( QWidget * parent, const char * name, WFlags f )
	: QWidget (parent, name, f)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);
	layout->addWidget (new QLabel (tr("Type in word(s) to search for:"), this));
	
	m_searchQuery = new QComboBox (TRUE, this);
	m_searchQuery->setFocus();
	m_searchQuery->setMaxCount (10);
	m_searchQuery->setSizePolicy ( QSizePolicy ( QSizePolicy::Expanding, QSizePolicy::Fixed ) );
	
	m_helpButton = new QPushButton ( tr("?"), this);
	m_helpButton->setSizePolicy ( QSizePolicy ( QSizePolicy::Minimum, QSizePolicy::Fixed ) );
	
	QHBoxLayout * hlayout = new QHBoxLayout ( layout );
	hlayout->addWidget ( m_searchQuery );
	hlayout->addWidget ( m_helpButton );
	
	m_searchList = new KQListView (this);
	m_searchList->addColumn( "Title" );
	m_searchList->addColumn( "Location" );
	m_searchList->setShowToolTips(true);

	connect( m_helpButton, SIGNAL( clicked () ), this, SLOT( onHelpClicked() ) );
	connect( m_searchQuery->lineEdit(), SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	connect( m_searchList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );

	m_matchSimilarWords = new QCheckBox (this);
	m_matchSimilarWords->setText (tr("Match similar words"));

	layout->addSpacing (10);
	layout->addWidget (m_searchList);
	layout->addWidget (m_matchSimilarWords);
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


inline static void mergeResults ( KCHMSearchProgressResults_t & results, const KCHMSearchProgressResults_t & src, bool add )
{
	if ( results.empty() && add )
	{
		results = src;
		return;
	}
	
	for ( unsigned int s1 = 0; s1 < results.size(); s1++ )
	{
		bool found = false;
	
		for ( unsigned int s2 = 0; s2 < src.size(); s2++ )
		{
			if ( results[s1].urloff == src[s2].urloff )
			{
				found = true;
				break;
			}
		}

		// If we're adding, we only add the items found (i.e. any item, which is not found, is removed.
		// But if we're removing, we only remove the items found.
		if ( (found && !add) || (!found && add) )
		{
			results.erase ( results.begin() + s1 );
			s1--;
		}
	}
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
		KCHMSearchProgressResults_t tempres;
		
		for ( i = 0; i < phrases_must_exist.size(); i++ )
		{
			if ( !searchPhrase ( phrases_must_exist[i], tempres ) )
				return false;
			
			mergeResults ( results, tempres, true );
		}
	}

	for ( i = 0; i < words_must_exist.size(); i++ )
	{
		KCHMSearchProgressResults_t tempres;
		
		if ( !searchWord ( words_must_exist[i], tempres ) )
			return false;

		mergeResults ( results, tempres, true );
	}

	for ( i = 0; i < words_must_not_exist.size(); i++ )
	{
		KCHMSearchProgressResults_t tempres;
		
		searchWord ( words_must_not_exist[i], tempres );
		mergeResults ( results, tempres, false );
	}

	::mainWindow->getChmFile()->GetSearchResults( results, searchresults, limit_results );
	return true;
}


static inline void findNextWords ( QValueVector<u_int64_t> & src, const QValueVector<u_int64_t> & needle )
{
	for ( unsigned int s1 = 0; s1 < src.size(); s1++ )
	{
		bool found = false;
		u_int64_t target_offset = src[s1] + 1;
		
		DEBUG_SEARCH (("Offset loop: offset at %u is %u, target %u", (unsigned int) s1,
					   (unsigned int) src[s1], (unsigned int) target_offset));
		
		// Search in the offsets list in attempt to find next word
		for ( unsigned int s2 = 0; s2 < needle.size(); s2++ )
		{
			if ( needle[s2] == target_offset )
			{
				found = true;
				break;
			}
		}

		if ( !found )
		{
			// Remove this offset, we don't need it anymore
			DEBUG_SEARCH (("Offset loop failed: offset %u not found", (unsigned int) target_offset));
			src.erase ( src.begin() + s1 );
			s1--;
		}
		else
		{
			DEBUG_SEARCH (("Offset loop succeed: offset %u found", (unsigned int) target_offset));
			src[s1]++;
		}
	}
}

//TODO: probably it's better to use list instead of vector
bool KCHMSearchWindow::searchPhrase( const QStringList & phrase, KCHMSearchProgressResults_t & results )
{
	// Accumulate the phrase data here.
	KCHMSearchProgressResults_t phrasekeeper;
	CHMFile * chm = ::mainWindow->getChmFile();

	// On the first word, just fill the phrasekeeper with every occupence of the first word
	DEBUG_SEARCH (("Search word(0): '%s'", phrase[0].ascii()));
	if ( !chm->SearchWord ( phrase[0], true, false, phrasekeeper, true ) )
		return false; // the word not found, so the whole phrase is not found either.

	for ( unsigned int i = 1; i < phrase.size(); i++ )
	{
		KCHMSearchProgressResults_t srchtmp;

		DEBUG_SEARCH (("Search word(%d): '%s'", i, phrase[i].ascii()));
		if ( !chm->SearchWord ( phrase[i], true, false, srchtmp, true ) )
			return false; // the ith word not found, so the whole phrase is not found either.

		// Iterate the both arrays, and remove every word in phrasekeeper, which is not found
		// in the srchtmp, or is found on a different position.
		for ( unsigned int p1 = 0; p1 < phrasekeeper.size(); p1++ )
		{
			bool found = false;
			
			DEBUG_SEARCH (("Ext loop (it %d): urloff %d", p1, phrasekeeper[p1].urloff));
			
			for ( unsigned int p2 = 0; p2 < srchtmp.size(); p2++ )
			{
				// look up for words on the the same page
				if ( srchtmp[p2].urloff != phrasekeeper[p1].urloff )
					continue;
				
				// Now check every offset to find the one which is 1 bigger than the 
				findNextWords ( phrasekeeper[p1].offsets, srchtmp[p2].offsets );
				
				// If at least one next word is found, we leave the block intact, otherwise remove it.
				if ( !phrasekeeper[p1].offsets.empty() )
					found = true;
			}
			
			if ( !found )
			{
				DEBUG_SEARCH (("Ext loop: this word not found on %d, remove it", phrasekeeper[p1].urloff));
				phrasekeeper.erase ( phrasekeeper.begin() + p1 );
				p1--;
			}
		}
	}

	for ( unsigned int o = 0; o < phrasekeeper.size(); o++ )
		results.push_back ( KCHMSearchProgressResult (phrasekeeper[o].titleoff, phrasekeeper[o].urloff) );
			
	return !results.empty();
}


bool KCHMSearchWindow::searchWord( const QString & word, KCHMSearchProgressResults_t & results )
{
	return ::mainWindow->getChmFile()->SearchWord(word, true, false, results, false );
}

void KCHMSearchWindow::onHelpClicked( )
{
	QMessageBox::information ( this, tr("How to use search"), tr("The search query can contain a few prefixes.\nA set of words inside the quote marks mean that you are searching for exact phrase.\nA word with minus sign means that it should be absent in the search result.\nA word with plus mark or without any mark means that it must be present in the search result.\n\nNote that only letters and digits are indexed.\nYou cannot search for symbols other than underscope, and these symbols will be removed from the search query.\nFor example, search for 'C' will give the same result as searching for 'C++'.") );
}
