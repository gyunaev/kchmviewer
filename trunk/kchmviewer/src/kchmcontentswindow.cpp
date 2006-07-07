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

#include "kde-qt.h"
#include "kchmcontentswindow.h"
#include "kchmlistitemtooltip.h"
#include "kchmmainwindow.h"
#include "kchmtreeviewitem.h"

KCHMContentsWindow::KCHMContentsWindow(QWidget *parent, const char *name)
 : KQListView(parent, name)
{
	m_contextMenu = 0;
	
	addColumn( "Contents" ); // no i18n - this column is hidden
	setSorting(-1);
	setFocus();
	setRootIsDecorated(true);
	header()->hide();
	setShowToolTips( false );
	
	connect( this, SIGNAL( onItem ( QListViewItem * ) ), this, SLOT( slotOnItem( QListViewItem * ) ) );
	connect( this, 
			 SIGNAL( contextMenuRequested( QListViewItem *, const QPoint& , int ) ),
			 this, 
			 SLOT( slotContextMenuRequested ( QListViewItem *, const QPoint &, int ) ) );

	
	new KCHMListItemTooltip( this );
}

KCHMContentsWindow::~KCHMContentsWindow()
{
}

void KCHMContentsWindow::slotContextMenuRequested( QListViewItem * item, const QPoint & point, int )
{
	if ( !m_contextMenu )
		m_contextMenu = ::mainWindow->getCurrentBrowser()->createListItemContextMenu( this );
		
	if( item )
	{
		KCHMMainTreeViewItem * treeitem = (KCHMMainTreeViewItem*) item;
		::mainWindow->getCurrentBrowser()->setTabKeeper( treeitem->getUrl() );
		m_contextMenu->popup( point );
	}
}

#include "kchmcontentswindow.moc"
