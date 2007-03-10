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

#include "libchmfile.h"

#include "kchmsearchwindow.h"
#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmlistitemtooltip.h"
#include "kchmtreeviewitem.h"
#include "kchmsearchengine.h"

#include "kchmsearchwindow.moc"


KCHMSearchWindow::KCHMSearchWindow( QWidget * parent, const char * name, WFlags f )
	: QWidget (parent, name, f)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);
	layout->addWidget (new QLabel (i18n( "Type in word(s) to search for:"), this));
	
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
	m_searchList->addColumn( i18n( "Title" ) );
	m_searchList->addColumn( i18n( "Location" ) );
	m_searchList->setShowToolTips(true);

	connect( m_helpButton, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onHelpClicked() ) );

	connect( m_searchQuery->lineEdit(), 
			 SIGNAL( returnPressed() ), 
			 this, 
			 SLOT( onReturnPressed() ) );
	
	connect( m_searchList, 
			 SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), 
			 this, 
			 SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );

	connect( m_searchList, 
			 SIGNAL( contextMenuRequested( QListViewItem *, const QPoint& , int ) ),
			 this, 
			 SLOT( slotContextMenuRequested ( QListViewItem *, const QPoint &, int ) ) );
	
	m_matchSimilarWords = new QCheckBox (this);
	m_matchSimilarWords->setText( i18n( "Match similar words") );

	layout->addSpacing (10);
	layout->addWidget (m_searchList);
//	layout->addWidget (m_matchSimilarWords);
	
	new KCHMListItemTooltip( m_searchList );
	m_contextMenu = 0;
	m_searchEngine = 0;
	m_useNewSearchEngine = false;
	m_newSearchEngineOffered = false;
	m_newSearchEngineBroken = false;
}

void KCHMSearchWindow::invalidate( )
{
	m_searchList->clear();
	m_searchQuery->clear();
	m_searchQuery->lineEdit()->clear();
}

void KCHMSearchWindow::onReturnPressed( )
{
	//if ( appConfig.m_useSearchEngine 
	if ( !m_searchEngine )
		initSearchEngine();
	
	QValueVector<LCHMSearchResult> results;
	QString text = m_searchQuery->lineEdit()->text();
	
	if ( text.isEmpty() )
		return;

	KCHMShowWaitCursor waitcursor;
	m_searchList->clear();
	
//	if ( ::mainWindow->chmFile()->searchQuery( text, &results ) )
	if ( m_searchEngine->searchQuery( text, &results ) )
	{
		if ( !results.empty() )
		{
			for ( unsigned int i = 0; i < results.size(); i++ )
			{
				new KCMSearchTreeViewItem (m_searchList, results[i].title, results[i].url, results[i].url);
			}

				::mainWindow->showInStatusBar( i18n( "Search returned %1 result(s)" ) . arg(results.size()) );
		}
		else
			::mainWindow->showInStatusBar( i18n( "Search returned no results") );
	}
	else
		::mainWindow->showInStatusBar( i18n( "Search failed") );
}

void KCHMSearchWindow::onDoubleClicked( QListViewItem *item, const QPoint &, int)
{
	if ( !item )
		return;
	
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) item;
	::mainWindow->openPage( treeitem->getUrl(), OPF_ADD2HISTORY );
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


void KCHMSearchWindow::onHelpClicked( )
{
	QMessageBox::information ( this, 
		i18n( "How to use search"), 
		i18n( "The search query can contain a few prefixes.\nA set of words inside the quote marks mean that you are searching for exact phrase.\nA word with minus sign means that it should be absent in the search result.\nA word with plus mark or without any mark means that it must be present in the search result.\n\nNote that only letters and digits are indexed.\nYou cannot search for non-character symbols other than underscope, and those symbols will be removed from the search query.\nFor example, search for 'C' will give the same result as searching for 'C++'.") );
}

void KCHMSearchWindow::slotContextMenuRequested( QListViewItem * item, const QPoint & point, int )
{
	if ( !m_contextMenu )
		m_contextMenu = ::mainWindow->currentBrowser()->createListItemContextMenu( this );
		
	if( item )
	{
		KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) item;
		
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		m_contextMenu->popup( point );
	}
}

bool KCHMSearchWindow::initSearchEngine( )
{
	m_searchEngine = new KCHMSearchEngine();
	
	if ( !m_searchEngine->loadOrGenerateIndex() )
	{
		m_useNewSearchEngine = false;
		m_newSearchEngineBroken = true;
		
		delete m_searchEngine;
		m_searchEngine = 0;
		return false;
	}
	
	m_useNewSearchEngine = true;
	m_newSearchEngineBroken = false;
	
	return true;
}
