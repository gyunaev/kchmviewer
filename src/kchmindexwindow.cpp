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

#include <qlayout.h>
#include <q3header.h>
//Added by qt3to4:
#include <QShowEvent>
#include <Q3VBoxLayout>

#include "libchmfile.h"

#include "kchmmainwindow.h"
#include "kchmindexwindow.h"
#include "kchmlistitemtooltip.h"
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
	
	m_indexListFilled = false;
	m_lastSelectedItem = 0;
	m_contextMenu = 0;
	
	// FIXME: tooltips, context menu
	// new KCHMListItemTooltip( m_indexList );
	
	text->setFocus();
}

void KCHMIndexWindow::onTextChanged ( const QString & newvalue)
{
	// FIXME: index search
	/*
	m_lastSelectedItem = tree->findItem (newvalue, 0, Qt::BeginsWith);
	
	if ( m_lastSelectedItem )
	{
		m_indexList->ensureItemVisible (m_lastSelectedItem);
		m_indexList->setCurrentItem (m_lastSelectedItem);
	}
	*/
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
	emit ::mainWindow->slotOnTreeClicked ( m_lastSelectedItem );
}


void KCHMIndexWindow::invalidate( )
{
	tree->clear();
	m_indexListFilled = false;
}

void KCHMIndexWindow::onDoubleClicked ( QTreeWidgetItem * item, int )
{
	/*
	FIXME!!!
	if ( !item )
		return;
	
	KCHMIndTocItem * treeitem = (KCHMIndTocItem*) item;
	
	QString url = treeitem->getUrl();
	
	if ( url.isEmpty() )
		return;

	if ( url[0] == ':' ) // 'see also' link
	{
		m_lastSelectedItem = tree->findItem (url.mid(1), 0);
		if ( m_lastSelectedItem )
		{
			tree->ensureItemVisible (m_lastSelectedItem);
			tree->setCurrentItem (m_lastSelectedItem);
		}
	}
	else
		::mainWindow->openPage( url, OPF_CONTENT_TREE | OPF_ADD2HISTORY );
	*/
}

/*
void KCHMIndexWindow::slotContextMenuRequested( Q3ListViewItem * item, const QPoint & point, int )
{
	if ( !m_contextMenu )
		m_contextMenu = ::mainWindow->currentBrowser()->createListItemContextMenu( this );
		
	if( item )
	{
		KCHMIndTocItem * treeitem = (KCHMIndTocItem*) item;
		
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->getUrl() );
		m_contextMenu->popup( point );
	}
}
*/
void KCHMIndexWindow::refillIndex( )
{
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
