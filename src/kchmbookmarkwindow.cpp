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
#include "kchmtreeviewitem.h"


class KCHMBookmarkTreeViewItem : public QListWidgetItem
{
	public:
		KCHMBookmarkTreeViewItem( QListWidget* parent, const QString& n, const QString& u, int s )
			: QListWidgetItem( n, parent ), url(u), name(n), scroll_y(s)
		{
			menuid = 0;
		}
	
		QString		url;
		QString		name;
		int			scroll_y;
		int			menuid;
};



KCHMBookmarkWindow::KCHMBookmarkWindow( QWidget *parent )
	: QWidget( parent ), Ui::TabBookmarks()
{
	// UIC code
	setupUi( this );
	
	// FIXME: tooltips!
	// FIXME: context menu
	// FIXME: bookmarks in menu, and menu
	//new KCHMListItemTooltip( list );
	
	connect( list,
			 SIGNAL( itemDoubleClicked ( QListWidgetItem* ) ),
			 this, 
	         SLOT( onItemDoubleClicked ( QListWidgetItem* ) ) );
	
	connect( btnAdd, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onAddBookmarkPressed( ) ) );
	
	connect( btnDel, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onDelBookmarkPressed( ) ) );
	
	connect( btnEdit, 
			 SIGNAL( clicked () ), 
			 this, 
			 SLOT( onEditBookmarkPressed( ) ) );
	
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
			list, 
			name, 
			url, 
			::mainWindow->currentBrowser()->getScrollbarPosition() );
	
	item->menuid = m_menuBookmarks->insertItem( name );
	m_listChanged = true;
}


void KCHMBookmarkWindow::onDelBookmarkPressed( )
{
	KCHMBookmarkTreeViewItem * item = (KCHMBookmarkTreeViewItem *) list->currentItem();
	
	if ( item )
	{
		m_menuBookmarks->removeItem( item->menuid );
		delete item;
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::onEditBookmarkPressed( )
{
	KCHMBookmarkTreeViewItem * item = (KCHMBookmarkTreeViewItem *) list->currentItem();
	
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

		item->setText( name );
		m_menuBookmarks->changeItem( item->menuid, name );
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::restoreSettings( const KCHMSettings::bookmark_saved_settings_t & settings )
{
	for ( int i = 0; i < settings.size(); i++ )
	{
		KCHMBookmarkTreeViewItem * item = new KCHMBookmarkTreeViewItem (list, settings[i].name, settings[i].url, settings[i].scroll_y);
		
		item->menuid = m_menuBookmarks->insertItem( settings[i].name );
	}
}


void KCHMBookmarkWindow::saveSettings( KCHMSettings::bookmark_saved_settings_t & settings )
{
	settings.clear();

	for ( int i = 0; i < list->count(); i++ )
	{
		KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) list->item( i );
		settings.push_back (KCHMSettings::SavedBookmark(treeitem->name, treeitem->url, treeitem->scroll_y));
    }
}

void KCHMBookmarkWindow::invalidate( )
{
	for ( int i = 0; i < list->count(); i++ )
		m_menuBookmarks->removeItem( ((KCHMBookmarkTreeViewItem *) list->item( i ))->menuid );

	list->clear();
}

void KCHMBookmarkWindow::createMenu( QMenu * menuBookmarks )
{
	m_menuBookmarks = menuBookmarks;
}

void KCHMBookmarkWindow::onBookmarkSelected( int bookmark )
{
	/*
	for ( int i = 0; i < list->count(); i++ )
	{
		KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) list->item( i );
		
		if ( treeitem->menuid == bookmark )
		{
			if ( ::mainWindow->currentBrowser()->getOpenedPage() != treeitem->url )
				::mainWindow->openPage( treeitem->url, OPF_CONTENT_TREE | OPF_ADD2HISTORY );
	
			::mainWindow->currentBrowser()->setScrollbarPosition(treeitem->scroll_y);
			break;
		}
	}
	*/
}


void KCHMBookmarkWindow::onItemDoubleClicked(QListWidgetItem *item)
{
	if ( !item )
		return;
	
	KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) item;
	
	if ( ::mainWindow->currentBrowser()->getOpenedPage() != treeitem->url )
		::mainWindow->openPage( treeitem->url, KCHMMainWindow::OPF_CONTENT_TREE | KCHMMainWindow::OPF_ADD2HISTORY );
	
	::mainWindow->currentBrowser()->setScrollbarPosition(treeitem->scroll_y);
}


/*
	if ( !m_contextMenu )
	m_contextMenu = ::mainWindow->currentBrowser()->createListItemContextMenu( this );
		
	if( item )
	{
	KCHMBookmarkTreeViewItem * treeitem = (KCHMBookmarkTreeViewItem *) item;
		
	::mainWindow->currentBrowser()->setTabKeeper( treeitem->url );
	m_contextMenu->popup( point );
*/
