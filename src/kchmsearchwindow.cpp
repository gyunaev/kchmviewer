/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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
	layout->setMargin(6);
	layout->setSpacing(6);
	
	// Labels <type words to search> and <help>
	QHBoxLayout * labellayout = new QHBoxLayout();
	labellayout->addWidget( new QLabel( i18n( "Type in word(s) to search for:"), this) );
	labellayout->addStretch( 10 );
	
	KCHMClickableLabel * helplink = new KCHMClickableLabel( i18n( "<a href=\"q\"><b>Help</b></a>"), this );
	connect( helplink, SIGNAL( clicked() ), this, SLOT( onHelpClicked() ) );
	helplink->setCursor( QCursor( Qt::PointingHandCursor ) );
	
	labellayout->addWidget ( helplink );
	layout->addLayout( labellayout );
	
	m_searchQuery = new QComboBox (TRUE, this);
	m_searchQuery->setFocus();
	m_searchQuery->setMaxCount (10);
	m_searchQuery->setSizePolicy ( QSizePolicy ( QSizePolicy::Expanding, QSizePolicy::Fixed ) );
	
	QPushButton * searchButton = new QPushButton ( i18n("Button which starts Search; must be small!", "Go"), this);
	searchButton->setSizePolicy ( QSizePolicy ( QSizePolicy::Minimum, QSizePolicy::Fixed ) );
	
	QHBoxLayout * hlayout = new QHBoxLayout ( layout );
	hlayout->addWidget ( m_searchQuery );
	hlayout->addWidget ( searchButton );
	
	m_searchList = new KQListView (this);
	m_searchList->addColumn( i18n( "Title" ) );
	m_searchList->addColumn( i18n( "Location" ) );
	m_searchList->setShowToolTips(true);

	connect( searchButton, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onReturnPressed() ) );

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
	
	//layout->addSpacing (10);
	layout->addWidget (m_searchList);
	
	new KCHMListItemTooltip( m_searchList );
	m_contextMenu = 0;
	m_searchEngine = 0;
	
	//FIXME! remove
	appConfig.m_useSearchEngine = KCHMConfig::SEARCH_USE_MINE;
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
	if ( appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_MINE )
	{
		QMessageBox::information ( this, 
			i18n( "How to use search"), 
			i18n( "<html><p>The improved search engine allows you to search for a word, symbol or phrase, which is set of words and symbols included in quotes. Only the documents which include all the terms speficide in th search query are shown; no prefixes needed.<p>Unlike MS CHM internal search index, my improved search engine indexes everything, including special symbols. Therefore it is possible to search (and find!) for something like <i>$q = new ChmFile();</i>. This search also fully supports Unicode, which means that you can search in non-English documents.<p>If you want to search for a quote symbol, use quotation mark instead. The engine treats a quote and a quotation mark as the same symbol, which allows to use them in phrases.</html>") );
	}
	else
	{
		QMessageBox::information ( this, 
			i18n( "How to use search"), 
			i18n( "The search query can contain a few prefixes.\nA set of words inside the quote marks mean that you are searching for exact phrase.\nA word with minus sign means that it should be absent in the search result.\nA word with plus mark or without any mark means that it must be present in the search result.\n\nNote that only letters and digits are indexed.\nYou cannot search for non-character symbols other than underscope, and those symbols will be removed from the search query.\nFor example, search for 'C' will give the same result as searching for 'C++'.") );
	}
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
		delete m_searchEngine;
		m_searchEngine = 0;
		return false;
	}
	
	return true;
}

void KCHMSearchWindow::searchQuery( const QString & query )
{
	m_searchQuery->lineEdit()->setText( query );
	onReturnPressed();
}
