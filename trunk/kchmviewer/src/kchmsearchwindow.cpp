
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
#define USE_GEORGE_SEARCH_ENGINE

#include <qlayout.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qstatusbar.h>
#include <qmessagebox.h>
#include <qregexp.h>

#include "kchmmainwindow.h"
#include "kchmsearchwindow.h"
#include "kchmexternalsearch.h"
#include "kchmconfig.h"
#include "xchmfile.h"

#if defined (USE_GEORGE_SEARCH_ENGINE)
	#include "kchmexternalsearchengine.h"
#endif

KCHMSearchWindow::KCHMSearchWindow( QWidget * parent, const char * name, WFlags f )
	: QWidget (parent, name, f)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	m_searchQuery = new QComboBox (TRUE, this);
	m_searchQuery->setFocus();
	m_searchQuery->setMaxCount (10);
	
	m_chooseSearchEngine = new QComboBox (this);

	m_searchList = new QListView (this);
	m_searchList->addColumn( "Title" );
	m_searchList->addColumn( "Location" );
		
	connect( (m_searchQuery->lineEdit()), SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	connect( m_searchList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );
//	connect( m_chooseSearchEngine, SIGNAL( currentChanged ( QListBoxItem *) ), this, SLOT( onCurrentChanged ( QListBoxItem *) ) );

	m_matchSimilarWords = new QCheckBox (this);
	m_matchSimilarWords->setText (tr("Match similar words"));

	m_searchInResult = new QCheckBox (this);
	m_searchInResult->setText (tr("Search in result"));
	
	layout->addWidget (new QLabel (tr("Use search engine:"), this));
	layout->addWidget (m_chooseSearchEngine);
	layout->addWidget (new QLabel (tr("Type in word(s) to search for:"), this));
	layout->addWidget (m_searchQuery);
	layout->addSpacing (10);
	layout->addWidget (m_searchList);
	layout->addWidget (m_matchSimilarWords);
	layout->addWidget (m_searchInResult);

	m_searchEngine = new KCHMSearchEngine ();
}

void KCHMSearchWindow::invalidate( )
{
	m_searchList->clear();
	m_searchQuery->clear();
	m_searchQuery->lineEdit()->clear();

	m_chooseSearchEngine->clear();

	// If there is internal search index, add the possibility to search on it
#if defined (USE_GEORGE_SEARCH_ENGINE)
	m_chooseSearchEngine->insertItem (tr("Advanced search"));
#endif

	// And set the current
#if defined (USE_GEORGE_SEARCH_ENGINE)
	m_searchEngine->setSearchBackend ( new KCHMSearchEngineGeorge );
#endif
}

void KCHMSearchWindow::onReturnPressed( )
{
	KCHMSearchEngine::searchResults results;
	QString text = m_searchQuery->lineEdit()->text();
	
	if ( text.isEmpty() )
		return;

	if ( !checkAndGenerateIndex( ) )
		return;

	m_searchList->clear();
	
	if ( m_searchEngine->doSearch ( text, results ) )
	{
		if ( !results.empty() )
		{
			for ( KCHMSearchEngine::searchResults::const_iterator it = results.begin(); it != results.end(); it++ )
				new KCMSearchTreeViewItem (m_searchList, it.data(), it.key(), it.key());
		
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

//void KCHMSearchWindow::onCurrentChanged( QListBoxItem * item )
//{
//}

bool KCHMSearchWindow::checkAndGenerateIndex( )
{
	if ( m_searchEngine->hasValidIndex() )
		return true;
	
   	if ( QMessageBox::question(this,
		tr ("%1 - need to create the search index") . arg(APP_NAME),
       	tr ("This file has not been indexed yet.\nThe search engine needs to create the index on this file.\n\nDo you want to proceed?"),
       	tr("&Yes"), tr("&No"),
       	QString::null, 0, 1 ) == 0 )
	{
		if ( m_searchEngine->createIndex() )
			return true;
	}

	return false;
}
