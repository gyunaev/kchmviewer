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

#include "kchmbookmarkwindow.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmlistitemtooltip.h"
#include "kchmtreeviewitem.h"

#include "kchmbookmarkwindow.moc"

KCHMBookmarkWindow::KCHMBookmarkWindow(QWidget *parent, const char *name)
 : QWidget(parent, name)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	m_bookmarkList = new KQListView (this);
	m_bookmarkList->addColumn( "bookmark" ); // no need to i18n - the column is hidden
	m_bookmarkList->header()->hide();
	layout->addWidget (m_bookmarkList);

	new KCHMListItemTooltip( m_bookmarkList );
	
	QHBoxLayout * hlayout = new QHBoxLayout (layout);
	QPushButton * add = new QPushButton ( i18n( "&Add" ), this);
	QPushButton * edit = new QPushButton ( i18n( "&Edit" ), this);
	QPushButton * del = new QPushButton ( i18n( "&Del" ), this);
	
	hlayout->addWidget (add);
	hlayout->addWidget (edit);
	hlayout->addWidget (del);
	
	connect( m_bookmarkList, 
			 SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), 
			 this, 
			 SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );
	
	connect( add, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onAddBookmarkPressed( ) ) );
	
	connect( del, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onDelBookmarkPressed( ) ) );
	
	connect( edit, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onEditBookmarkPressed( ) ) );
	
	connect( m_bookmarkList, 
			 SIGNAL( contextMenuRequested( QListViewItem *, const QPoint& , int ) ),
			 this, 
			 SLOT( slotContextMenuRequested ( QListViewItem *, const QPoint &, int ) ) );

	m_menuBookmarks = 0;
	m_contextMenu = 0;
	m_listChanged = false;
}

void KCHMBookmarkWindow::onAddBookmarkPressed( )
{
    bool ok;
	QString url = ::mainWindow->currentBrowser()->getOpenedPage();
	QString title = ::mainWindow->chmFile()->getTopicByUrl(url);
	QString name = QInputDialog::getText( 
			i18n( "%1 - add a bookmark") . arg(APP_NAME),
			i18n( "Enter the name for this bookmark:" ),
			QLineEdit::Normal,
			title,
			&ok, 
			this);
    
	if ( !ok || name.isEmpty() )
		return;

	KCHMBookmarkTreeViewItem * item = new KCHMBookmarkTreeViewItem (
			m_bookmarkList, 
			name, 
			url, 
			::mainWindow->currentBrowser()->getScrollbarPosition() );
	
	item->menuid = m_menuBookmarks->insertItem( name );
	m_listChanged = true;
}


void KCHMBookmarkWindow::onDelBookmarkPressed( )
{
	KCHMBookmarkTreeViewItem * item = (KCHMBookmarkTreeViewItem *) m_bookmarkList->selectedItem();
	
	if ( item )
	{
		m_menuBookmarks->removeItem( item->menuid );
		delete item;
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::onEditBookmarkPressed( )
{
	KCHMBookmarkTreeViewItem * item = (KCHMBookmarkTreeViewItem *) m_bookmarkList->selectedItem();
	
	if ( item )
	{
	    bool ok;
		QString name = QInputDialog::getText( 
			i18n( "%1 - edit the bookmark name") . arg(APP_NAME),
			i18n( "Enter the name for this bookmark:" ),
			QLineEdit::Normal,
			item->name, 
			&ok, 
			this);
    
		if ( !ok || name.isEmpty() )
			return;

		item->setText (0, name);
		m_menuBookmarks->changeItem( item->menuid, name );
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::onDoubleClicked( QListViewItem * item, const QPoint &, int )
{
	if ( !item )
		return;
	
	KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) item;
	
	if ( ::mainWindow->currentBrowser()->getOpenedPage() != treeitem->url )
		::mainWindow->openPage( treeitem->url, OPF_CONTENT_TREE | OPF_ADD2HISTORY );
	
	::mainWindow->currentBrowser()->setScrollbarPosition(treeitem->scroll_y);
}


void KCHMBookmarkWindow::restoreSettings( const KCHMSettings::bookmark_saved_settings_t & settings )
{
	for ( unsigned int i = 0; i < settings.size(); i++ )
	{
		KCHMBookmarkTreeViewItem * item = new KCHMBookmarkTreeViewItem (m_bookmarkList, settings[i].name, settings[i].url, settings[i].scroll_y);
		
		item->menuid = m_menuBookmarks->insertItem( settings[i].name );
	}
}


void KCHMBookmarkWindow::saveSettings( KCHMSettings::bookmark_saved_settings_t & settings )
{
    QListViewItemIterator it (m_bookmarkList);

	settings.clear();

	for ( ; it.current(); it++ )
	{
		KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) it.current();
		settings.push_back (KCHMSettings::SavedBookmark(treeitem->name, treeitem->url, treeitem->scroll_y));
    }
}

void KCHMBookmarkWindow::invalidate( )
{
	QListViewItemIterator it( m_bookmarkList );
	
	for ( ; it.current(); it++ )
		m_menuBookmarks->removeItem( ((KCHMBookmarkTreeViewItem *) it.current())->menuid );

	m_bookmarkList->clear();
}

void KCHMBookmarkWindow::createMenu( KCHMMainWindow * parent )
{
	// Create the main Bookmark menu
	m_menuBookmarks = new KQPopupMenu( parent );
	parent->menuBar()->insertItem( i18n( "&Bookmarks"), m_menuBookmarks );

	m_menuBookmarks->insertItem( i18n( "&Add bookmark"), this, SLOT(onAddBookmarkPressed()), CTRL+Key_B );
	m_menuBookmarks->insertSeparator();

	connect( m_menuBookmarks, SIGNAL( activated(int) ), this, SLOT ( onBookmarkSelected(int) ));
}

void KCHMBookmarkWindow::onBookmarkSelected( int bookmark )
{
	QListViewItemIterator it( m_bookmarkList );
	
	for ( ; it.current(); it++ )
	{
		if ( ((KCHMBookmarkTreeViewItem *) it.current())->menuid == bookmark )
		{
			KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) it.current();
	
			if ( ::mainWindow->currentBrowser()->getOpenedPage() != treeitem->url )
				::mainWindow->openPage( treeitem->url, OPF_CONTENT_TREE | OPF_ADD2HISTORY );
	
			::mainWindow->currentBrowser()->setScrollbarPosition(treeitem->scroll_y);
			break;
		}
	}
}

void KCHMBookmarkWindow::slotContextMenuRequested( QListViewItem * item, const QPoint & point, int )
{
	if ( !m_contextMenu )
		m_contextMenu = ::mainWindow->currentBrowser()->createListItemContextMenu( this );
		
	if( item )
	{
		KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) item;
		
		::mainWindow->currentBrowser()->setTabKeeper( treeitem->url );
		m_contextMenu->popup( point );
	}
}

