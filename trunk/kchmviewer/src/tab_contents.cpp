/**************************************************************************
 *  Kchmviewer - a portable CHM file viewer with the best support for     *
 *  the international languages                                           *
 *                                                                        *
 *  Copyright (C) 2004-2012 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  Please read http://www.kchmviewer.net/reportbugs.html if you want     *
 *  to report a bug. It lists things I need to fix it!                    *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#include "kde-qt.h"

#include "libchmfile.h"
#include "libchmurlfactory.h"

#include "mainwindow.h"
#include "treeviewitem.h"
#include "tab_contents.h"


TabContents::TabContents( QWidget *parent )
	: QWidget( parent ), Ui::TabContents()
{
	setupUi( this );
	
	m_contextMenu = 0;
	
	tree->header()->hide();
	
	// Handle clicking on m_contentsWindow element
	connect( tree, 
			 SIGNAL( itemActivated ( QTreeWidgetItem *, int ) ),
	         this, 
	         SLOT( onClicked ( QTreeWidgetItem *, int ) ) );
	
	// Activate custom context menu, and connect it
	tree->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( tree, 
	         SIGNAL( customContextMenuRequested ( const QPoint & ) ),
	         this, 
	         SLOT( onContextMenuRequested( const QPoint & ) ) );

	if ( ::mainWindow->chmFile() )
		refillTableOfContents();

	focus();
}

TabContents::~TabContents()
{
}

void TabContents::refillTableOfContents( )
{
	ShowWaitCursor wc;
	QVector< LCHMParsedEntry > data;
	
	if ( !::mainWindow->chmFile()->parseTableOfContents( &data )
	|| data.size() == 0 )
	{
		qWarning ("CHM toc present but is empty; wrong parsing?");
		return;
	}
			   
	kchmFillListViewWithParsedData( tree, data, &m_urlListMap );
}


IndexTocItem * TabContents::getTreeItem( const QString & url )
{
	QMap<QString, IndexTocItem*>::const_iterator it;

	// First try to find non-normalized URL (present in some ugly CHM files)
	it = m_urlListMap.find( LCHMUrlFactory::makeURLabsoluteIfNeeded(url) );

	if ( it == m_urlListMap.end() )
	{
		QString fixedstr = ::mainWindow->chmFile()->normalizeUrl( url );
		it = m_urlListMap.find( fixedstr );
	}

	if ( it == m_urlListMap.end() )
		return 0;
		
	return *it;
}

void TabContents::showItem( IndexTocItem * item )
{
	tree->setCurrentItem( item );
	tree->scrollToItem( item );
}


void TabContents::onClicked(QTreeWidgetItem * item, int)
{
	if ( !item )
		return;
	
	IndexTocItem * treeitem = (IndexTocItem*) item;
	::mainWindow->activateLink( treeitem->getUrl() );
}

void TabContents::onContextMenuRequested(const QPoint & point)
{
	IndexTocItem * treeitem = (IndexTocItem *) tree->itemAt( point );
	
	if( treeitem )
	{
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		::mainWindow->tabItemsContextMenu()->popup( tree->viewport()->mapToGlobal( point ) );
	}
}


void TabContents::search( const QString & text )
{
	QList<QTreeWidgetItem*> items = tree->findItems( text, Qt::MatchWildcard | Qt::MatchRecursive );

	if ( items.isEmpty() )
		return;
			
	IndexTocItem * treeitem = (IndexTocItem *) items.first();
	::mainWindow->activateLink( treeitem->getUrl() );
}

void TabContents::focus()
{
	if ( !tree->hasFocus() )
		tree->setFocus();
}
