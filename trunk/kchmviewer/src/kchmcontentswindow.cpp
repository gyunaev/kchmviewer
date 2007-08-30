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


#include "kde-qt.h"

#include "libchmfile.h"

#include "kchmcontentswindow.h"
#include "kchmmainwindow.h"
#include "kchmtreeviewitem.h"


KCHMContentsWindow::KCHMContentsWindow( QWidget *parent )
	: QWidget( parent ), Ui::TabContents()
{
	setupUi( this );
	
	m_contextMenu = 0;
	m_contentFilled = false;
	
	tree->setFocus();
	tree->header()->hide();
	
	// Handle clicking on m_contentsWindow element
	connect( tree, 
	         SIGNAL( itemClicked ( QTreeWidgetItem *, int ) ), 
	         this, 
	         SLOT( onClicked ( QTreeWidgetItem *, int ) ) );
	
	// Activate custom context menu, and connect it
	tree->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( tree, 
	         SIGNAL( customContextMenuRequested ( const QPoint & ) ),
	         this, 
	         SLOT( onContextMenuRequested( const QPoint & ) ) );
}

KCHMContentsWindow::~KCHMContentsWindow()
{
}

void KCHMContentsWindow::refillTableOfContents( )
{
	QVector< LCHMParsedEntry > data;
	
	if ( !::mainWindow->chmFile()->parseTableOfContents( &data )
	|| data.size() == 0 )
	{
		qWarning ("CHM toc present but is empty; wrong parsing?");
		return;
	}
			   
	kchmFillListViewWithParsedData( tree, data, &m_urlListMap );
}


KCHMIndTocItem * KCHMContentsWindow::getTreeItem( const QString & url )
{
	QString fixedstr = ::mainWindow->chmFile()->normalizeUrl( url );
	QMap<QString, KCHMIndTocItem*>::const_iterator it = m_urlListMap.find( fixedstr );
	
	if ( it == m_urlListMap.end() )
		return 0;
		
	return *it;
}

void KCHMContentsWindow::showItem(KCHMIndTocItem * item)
{
	tree->setCurrentItem( item );
	tree->scrollToItem( item );
}

void KCHMContentsWindow::showEvent(QShowEvent *)
{
	if ( !::mainWindow->chmFile() || m_contentFilled )
		return;
	
	m_contentFilled = true;
	refillTableOfContents();
}

void KCHMContentsWindow::onClicked(QTreeWidgetItem * item, int)
{
	bool unused;
	
	if ( !item )
		return;
	
	KCHMIndTocItem * treeitem = (KCHMIndTocItem*) item;
	::mainWindow->activateLink( treeitem->getUrl(), unused );
}

void KCHMContentsWindow::onContextMenuRequested(const QPoint & point)
{
	KCHMIndTocItem * treeitem = (KCHMIndTocItem *) tree->itemAt( point );
	
	if( treeitem )
	{
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		::mainWindow->tabItemsContextMenu()->popup( tree->viewport()->mapToGlobal( point ) );
	}
}
