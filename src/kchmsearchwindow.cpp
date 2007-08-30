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

#include <QHeaderView>

#include "libchmfile.h"

#include "kchmsearchwindow.h"
#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmtreeviewitem.h"
#include "kchmsearchengine.h"



class KCMSearchTreeViewItem : public QTreeWidgetItem
{
	public:
		KCMSearchTreeViewItem( QTreeWidget * tree, const QString& name, const QString& url )
			:	QTreeWidgetItem( tree ), m_name( name ), m_url( url ) {};
	
		QString		getUrl() const { return m_url; }
	
	protected:
		// Overriden members
	int columnCount () const	{ return 2; }
	
		// Overriden member
		QVariant data ( int column, int role ) const
		{
			switch( role )
			{
				// Item name
				case Qt::DisplayRole:
				case Qt::ToolTipRole:
				case Qt::WhatsThisRole:
				if ( column == 0 )
					return m_name;
				else
					return m_url;
			}
			
			return QVariant();
		}
	
	private:
		QString		m_name;		
		QString		m_url;
};



KCHMSearchWindow::KCHMSearchWindow( QWidget * parent )
	: QWidget( parent ), Ui::TabSearch()
{
	// UIC stuff
	setupUi( this );
	
	// Clickable Help label
	connect( lblHelp, 
	         SIGNAL( linkActivated( const QString & ) ), 
	         this, 
	         SLOT( onHelpClicked(const QString & ) ) );
	
	// Go Button
	connect( btnGo, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onReturnPressed() ) );

	// Pressing 'Return' in the combo box line edit
	connect( searchBox->lineEdit(), 
			 SIGNAL( returnPressed() ), 
			 this, 
			 SLOT( onReturnPressed() ) );
	
	// Clicking on tree element
	connect( tree, 
	         SIGNAL( itemDoubleClicked( QTreeWidgetItem *, int ) ), 
			 this, 
	         SLOT( onDoubleClicked( QTreeWidgetItem *, int ) ) );

	// Activate custom context menu, and connect it
	tree->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( tree, 
			 SIGNAL( customContextMenuRequested ( const QPoint & ) ),
			 this, 
			 SLOT( onContextMenuRequested( const QPoint & ) ) );

	searchBox->setFocus();
	
	m_contextMenu = 0;
	m_searchEngine = 0;
}

void KCHMSearchWindow::invalidate( )
{
	tree->clear();
	searchBox->clear();
	searchBox->lineEdit()->clear();
	
	delete m_searchEngine;
	m_searchEngine = 0;
}

void KCHMSearchWindow::onReturnPressed( )
{
	QStringList results;
	QString text = searchBox->lineEdit()->text();
	
	if ( text.isEmpty() )
		return;
	
	tree->clear();
	
	if ( searchQuery( text, &results ) )
	{
		if ( !results.empty() )
		{
			for ( int i = 0; i < results.size(); i++ )
			{
				new KCMSearchTreeViewItem ( tree,
				                            ::mainWindow->chmFile()->getTopicByUrl( results[i] ),
										 	results[i] );
			}

			::mainWindow->showInStatusBar( i18n( "Search returned %1 result(s)" ) . arg(results.size()) );
		}
		else
			::mainWindow->showInStatusBar( i18n( "Search returned no results") );
	}
	else
		::mainWindow->showInStatusBar( i18n( "Search failed") );
}


void KCHMSearchWindow::onDoubleClicked( QTreeWidgetItem * item, int )
{
	if ( !item )
		return;
	
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) item;
	::mainWindow->openPage( treeitem->getUrl(), KCHMMainWindow::OPF_ADD2HISTORY );
}

void KCHMSearchWindow::restoreSettings( const KCHMSettings::search_saved_settings_t & settings )
{
	for ( int i = 0; i < settings.size(); i++ )
		searchBox->insertItem (settings[i]);
}

void KCHMSearchWindow::saveSettings( KCHMSettings::search_saved_settings_t & settings )
{
	settings.clear();

	for ( int i = 0; i < searchBox->count(); i++ )
		settings.push_back (searchBox->text(i));
}


void KCHMSearchWindow::onHelpClicked( const QString & )
{
	if ( appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_MINE )
	{
		QToolTip::showText ( mapToGlobal( lblHelp->pos() ),
		                     i18n( "<html><p>The improved search engine allows you to search for a word, symbol or phrase, which is set of words and symbols included in quotes. Only the documents which include all the terms speficide in th search query are shown; no prefixes needed.<p>Unlike MS CHM internal search index, my improved search engine indexes everything, including special symbols. Therefore it is possible to search (and find!) for something like <i>$q = new ChmFile();</i>. This search also fully supports Unicode, which means that you can search in non-English documents.<p>If you want to search for a quote symbol, use quotation mark instead. The engine treats a quote and a quotation mark as the same symbol, which allows to use them in phrases.</html>") );
	}
	else
	{
		QMessageBox::information ( this, 
			i18n( "How to use search"), 
			i18n( "The search query can contain a few prefixes.\nA set of words inside the quote marks mean that you are searching for exact phrase.\nA word with minus sign means that it should be absent in the search result.\nA word with plus mark or without any mark means that it must be present in the search result.\n\nNote that only letters and digits are indexed.\nYou cannot search for non-character symbols other than underscope, and those symbols will be removed from the search query.\nFor example, search for 'C' will give the same result as searching for 'C++'.") );
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


void KCHMSearchWindow::execSearchQueryInGui( const QString & query )
{
	searchBox->lineEdit()->setText( query );
	onReturnPressed();
}


bool KCHMSearchWindow::searchQuery( const QString & query, QStringList * results )
{
	if ( appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_MINE )
	{
		if ( !m_searchEngine && !initSearchEngine() )
			return false;
	}
	else if ( !::mainWindow->chmFile()->hasSearchTable() )
	{
		QMessageBox::information ( this, 
					i18n( "Search is not available" ),
					i18n( "<p>The search feature is not avaiable for this chm file."
					"<p>The old search engine depends on indexes present in chm files itself. Not every chm file has an index; it is set up"
					" during chm file creation. Therefore if the search index was not created during chm file creation, this makes search "
					"impossible.<p>Solution: use new search engine (menu Settings/Advanced), which generates its own index.") );
		return false;
	}
	
	if ( query.isEmpty() )
		return false;

	KCHMShowWaitCursor waitcursor;
	bool result;
	
	if ( appConfig.m_useSearchEngine == KCHMConfig::SEARCH_USE_MINE )
		result = m_searchEngine->searchQuery( query, results );
	else
		result = ::mainWindow->chmFile()->searchQuery( query, results );

	return result;
}

//FIXME: add whatsthis to toolbar items/actions

void KCHMSearchWindow::onContextMenuRequested( const QPoint & point )
{
	KCMSearchTreeViewItem * treeitem = (KCMSearchTreeViewItem *) tree->itemAt( point );
	
	if( treeitem )
	{
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		::mainWindow->tabItemsContextMenu()->popup( tree->viewport()->mapToGlobal( point ) );
	}
}
