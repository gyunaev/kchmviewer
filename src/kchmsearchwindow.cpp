
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
	for ( int i = 0; i < m_searchQuery->count(); i++ )
		settings.push_back (m_searchQuery->text(i));
}

bool KCHMSearchWindow::searchQuery( const QString & query, KCHMSearchResults_t & results, unsigned int limit_results )
{
	// Parse the query
	QStringList words = QStringList::split (' ', query);

	if ( words.size() < 1 )
		return false;

	if ( !searchWord (words[0], results, limit_results, TYPE_OR) )
		return false;

	// Simple 'AND' search
	for ( unsigned int i = 1; i < words.size(); i++ )
	{
		if ( !searchWord (words[i], results, limit_results, TYPE_AND) )
			return false;
	}

	return true;
}

bool KCHMSearchWindow::searchWord( const QString & word, KCHMSearchResults_t & results, unsigned int limit_results, SearchType_t type)
{
	// OR is the simplest case - just fill the structure up.
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

	return true;
}
