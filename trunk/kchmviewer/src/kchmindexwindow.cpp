/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
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
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/


#include "libchmfile.h"

#include "kchmmainwindow.h"
#include "kchmindexwindow.h"
#include "kchmtreeviewitem.h"


KCHMIndexWindow::KCHMIndexWindow ( QWidget * parent )
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
			 SIGNAL( itemDoubleClicked ( QTreeWidgetItem *, int ) ), 
			 this, 
			 SLOT( onDoubleClicked ( QTreeWidgetItem *, int) ) );
	
	// Activate custom context menu, and connect it
	tree->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( tree, 
	         SIGNAL( customContextMenuRequested ( const QPoint & ) ),
	         this, 
	         SLOT( onContextMenuRequested( const QPoint & ) ) );
	
	m_indexListFilled = false;
	m_lastSelectedItem = 0;
	m_contextMenu = 0;
	
	text->setFocus();
}

void KCHMIndexWindow::onTextChanged ( const QString & newvalue)
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


void KCHMIndexWindow::showEvent( QShowEvent * )
{
	if ( !::mainWindow->chmFile() || m_indexListFilled )
		return;

	m_indexListFilled = true;
	refillIndex();
}

void KCHMIndexWindow::onReturnPressed( )
{
	bool unused;
	
	if ( !m_lastSelectedItem )
		return;
	
	KCHMIndTocItem * treeitem = (KCHMIndTocItem*) m_lastSelectedItem;
	::mainWindow->activateLink( treeitem->getUrl(), unused );
}


void KCHMIndexWindow::invalidate( )
{
	tree->clear();
	m_indexListFilled = false;
}

void KCHMIndexWindow::onDoubleClicked ( QTreeWidgetItem * item, int )
{
	if ( !item )
		return;
	
	KCHMIndTocItem * treeitem = (KCHMIndTocItem*) item;
	
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
		::mainWindow->openPage( url, KCHMMainWindow::OPF_CONTENT_TREE | KCHMMainWindow::OPF_ADD2HISTORY );
}


void KCHMIndexWindow::refillIndex( )
{
	KCHMShowWaitCursor wc;
	QVector< LCHMParsedEntry > data;
	
	if ( !::mainWindow->chmFile()->parseIndex( &data )
			   || data.size() == 0 )
	{
		qWarning ("CHM index present but is empty; wrong parsing?");
		return;
	}
	
	kchmFillListViewWithParsedData( tree, data, 0 );
}

void KCHMIndexWindow::search( const QString & index )
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

void KCHMIndexWindow::onContextMenuRequested(const QPoint & point)
{
	KCHMIndTocItem * treeitem = (KCHMIndTocItem *) tree->itemAt( point );
	
	if( treeitem )
	{
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		::mainWindow->tabItemsContextMenu()->popup( tree->viewport()->mapToGlobal( point ) );
	}
}
