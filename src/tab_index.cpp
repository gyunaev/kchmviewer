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

#include "libchmfile.h"

#include "mainwindow.h"
#include "treeviewitem.h"
#include "tab_index.h"


TabIndex::TabIndex ( QWidget * parent )
	: QWidget( parent ), Ui::TabIndex()
{
	// UIC stuff
	setupUi( this );
	
	tree->headerItem()->setHidden( true );
	
	connect( text,
			 SIGNAL( textChanged (const QString &) ), 
			 this, 
			 SLOT( onTextChanged(const QString &) ) );
	
	connect( text, 
			 SIGNAL( returnPressed() ), 
			 this, 
			 SLOT( onReturnPressed() ) );
	
	connect( tree,
			 SIGNAL( itemActivated(QTreeWidgetItem*, int)),
			 this,
			 SLOT( onItemActivated( QTreeWidgetItem*, int)) );


	// Activate custom context menu, and connect it
	tree->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( tree, 
	         SIGNAL( customContextMenuRequested ( const QPoint & ) ),
	         this, 
	         SLOT( onContextMenuRequested( const QPoint & ) ) );
	
	m_indexListFilled = false;
	m_lastSelectedItem = 0;
	m_contextMenu = 0;

	focus();
}

void TabIndex::onTextChanged ( const QString & newvalue)
{
	QList<QTreeWidgetItem *> items = tree->findItems( newvalue, Qt::MatchStartsWith );
	
	if ( !items.isEmpty() )
	{
		m_lastSelectedItem = items[0];
		tree->setCurrentItem( m_lastSelectedItem );
		tree->scrollToItem( m_lastSelectedItem );
	}
	else
		m_lastSelectedItem = 0;
}


void TabIndex::showEvent( QShowEvent * )
{
	if ( !::mainWindow->chmFile() || m_indexListFilled )
		return;

	m_indexListFilled = true;
	refillIndex();
}

void TabIndex::onReturnPressed( )
{
	if ( !m_lastSelectedItem )
		return;
	
	IndexTocItem * treeitem = (IndexTocItem*) m_lastSelectedItem;
	::mainWindow->activateLink( treeitem->getUrl() );
}


void TabIndex::invalidate( )
{
	tree->clear();
	m_indexListFilled = false;
	m_lastSelectedItem = 0;
}

void TabIndex::onItemActivated ( QTreeWidgetItem * item, int )
{
	if ( !item )
		return;
	
	IndexTocItem * treeitem = (IndexTocItem*) item;
	
	// Prevent opened index tree item from closing; because the tree open/close 
	// procedure will be triggered after the slots are called, we change the tree
	// state to "collapsed", so the slot handler expands it again.
	if ( item->isExpanded() )
		item->setExpanded( false );
	
	QString url = treeitem->getUrl();
	
	if ( url.isEmpty() )
		return;

	if ( url[0] == ':' ) // 'see also' link
	{
		QList<QTreeWidgetItem *> items = tree->findItems( url.mid(1), Qt::MatchFixedString );
	
		if ( !items.isEmpty() )
		{
			m_lastSelectedItem = items[0];
			tree->setCurrentItem( m_lastSelectedItem );
			tree->scrollToItem( m_lastSelectedItem );
		}
		else
			m_lastSelectedItem = 0;
	}
	else
		::mainWindow->openPage( url, MainWindow::OPF_CONTENT_TREE | MainWindow::OPF_ADD2HISTORY );
}


void TabIndex::refillIndex( )
{
	ShowWaitCursor wc;
	QVector< LCHMParsedEntry > data;
	
	if ( !::mainWindow->chmFile()->parseIndex( &data )
			   || data.size() == 0 )
	{
		qWarning ("CHM index present but is empty; wrong parsing?");
		return;
	}
	
	kchmFillListViewWithParsedData( tree, data, 0 );
}

void TabIndex::search( const QString & index )
{
	if ( !::mainWindow->chmFile() )
		return;

	if ( !m_indexListFilled )
	{
		m_indexListFilled = true;
		refillIndex();
	}

	text->setText( index );
	onTextChanged( index );
}

void TabIndex::focus()
{
	if ( !tree->hasFocus() )
		tree->setFocus();
}

void TabIndex::onContextMenuRequested(const QPoint & point)
{
	IndexTocItem * treeitem = (IndexTocItem *) tree->itemAt( point );
	
	if( treeitem )
	{
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		::mainWindow->tabItemsContextMenu()->popup( tree->viewport()->mapToGlobal( point ) );
	}
}
