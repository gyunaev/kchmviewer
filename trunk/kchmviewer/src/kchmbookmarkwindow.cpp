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

#include "kchmbookmarkwindow.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmtreeviewitem.h"
#include "version.h"

class KCHMBookmarkItem : public QListWidgetItem
{
	public:
		KCHMBookmarkItem( KCHMBookmarkWindow * widget, QListWidget* parent, const QString& name, const QString& url, int pos )
			: QListWidgetItem( parent )
		{
			m_name = name;
			m_url = url;
			m_scroll_y = pos;
			m_action = new QAction( name, widget );
			m_action->setData( qVariantFromValue( (void*) this ) );
			
			QObject::connect( m_action,
			         SIGNAL( triggered() ),
			         widget,
			         SLOT( actionBookmarkActivated() ) );
		}
	
		// Visualization
		virtual QVariant data ( int role ) const
		{
			switch ( role )
			{
			case Qt::ToolTipRole:
			case Qt::WhatsThisRole:
			case Qt::DisplayRole:
			     	return m_name;
			}
			
			return QVariant();
		}
	
		QString		m_name;
		QString		m_url;
		int			m_scroll_y;
		QAction *	m_action;
};



KCHMBookmarkWindow::KCHMBookmarkWindow( QWidget *parent )
	: QWidget( parent ), Ui::TabBookmarks()
{
	// UIC code
	setupUi( this );
	
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

	// Activate custom context menu, and connect it
	list->setContextMenuPolicy( Qt::CustomContextMenu );
	connect( list, 
	         SIGNAL( customContextMenuRequested ( const QPoint & ) ),
	         this, 
	         SLOT( onContextMenuRequested( const QPoint & ) ) );
}

void KCHMBookmarkWindow::onAddBookmarkPressed( )
{
    bool ok;
	QString url = ::mainWindow->currentBrowser()->getOpenedPage();
	QString title = ::mainWindow->chmFile()->getTopicByUrl(url);
	QString name = QInputDialog::getText( 
	        this,
			i18n( "%1 - add a bookmark") . arg(APP_NAME),
			i18n( "Enter the name for this bookmark:" ),
			QLineEdit::Normal,
			title,
			&ok );
    
	if ( !ok || name.isEmpty() )
		return;

	KCHMBookmarkItem * item = new KCHMBookmarkItem ( this,
	                                                 list, 
	                                                 name, 
	                                                 url, 
	                                                 ::mainWindow->currentBrowser()->getScrollbarPosition() );
	
	m_menuBookmarks->addAction( item->m_action );
	m_listChanged = true;
}


void KCHMBookmarkWindow::onDelBookmarkPressed( )
{
	KCHMBookmarkItem * item = (KCHMBookmarkItem *) list->currentItem();
	
	if ( item )
	{
		m_menuBookmarks->removeAction( item->m_action );
		delete item;
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::onEditBookmarkPressed( )
{
	KCHMBookmarkItem * item = (KCHMBookmarkItem *) list->currentItem();
	
	if ( item )
	{
	    bool ok;
		QString name = QInputDialog::getText( 
			this,
		    i18n( "%1 - edit the bookmark name") . arg(APP_NAME),
			i18n( "Enter the name for this bookmark:" ),
			QLineEdit::Normal,
			item->m_name, 
			&ok );
    
		if ( !ok || name.isEmpty() )
			return;

		item->setText( name );
		item->m_action->setText( name );
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::restoreSettings( const KCHMSettings::bookmark_saved_settings_t & settings )
{
	for ( int i = 0; i < settings.size(); i++ )
	{
		KCHMBookmarkItem * item = new KCHMBookmarkItem( this, list, settings[i].name, settings[i].url, settings[i].scroll_y );
		m_menuBookmarks->addAction( item->m_action );
	}
}


void KCHMBookmarkWindow::saveSettings( KCHMSettings::bookmark_saved_settings_t & settings )
{
	settings.clear();

	for ( int i = 0; i < list->count(); i++ )
	{
		KCHMBookmarkItem * treeitem = (KCHMBookmarkItem *) list->item( i );
		settings.push_back (KCHMSettings::SavedBookmark( treeitem->m_name, treeitem->m_url, treeitem->m_scroll_y) );
    }
}

void KCHMBookmarkWindow::invalidate( )
{
	for ( int i = 0; i < list->count(); i++ )
		m_menuBookmarks->removeAction( ((KCHMBookmarkItem *) list->item( i ))->m_action );

	list->clear();
}

void KCHMBookmarkWindow::createMenu( QMenu * menuBookmarks )
{
	m_menuBookmarks = menuBookmarks;
}

void KCHMBookmarkWindow::onItemDoubleClicked(QListWidgetItem * item)
{
	if ( !item )
		return;
	
	KCHMBookmarkItem * treeitem = (KCHMBookmarkItem *) item;
	
	if ( ::mainWindow->currentBrowser()->getOpenedPage() != treeitem->m_url )
		::mainWindow->openPage( treeitem->m_url, KCHMMainWindow::OPF_CONTENT_TREE | KCHMMainWindow::OPF_ADD2HISTORY );
	
	::mainWindow->currentBrowser()->setScrollbarPosition( treeitem->m_scroll_y );
}

void KCHMBookmarkWindow::actionBookmarkActivated()
{
	QAction *action = qobject_cast< QAction * >(sender());

	KCHMBookmarkItem * item = (KCHMBookmarkItem *) action->data().value< void* > ();
	
	if ( !item )
		return;
	
	if ( ::mainWindow->currentBrowser()->getOpenedPage() != item->m_url )
		::mainWindow->openPage( item->m_url, KCHMMainWindow::OPF_CONTENT_TREE | KCHMMainWindow::OPF_ADD2HISTORY );
	
	::mainWindow->currentBrowser()->setScrollbarPosition( item->m_scroll_y );
}

void KCHMBookmarkWindow::onContextMenuRequested(const QPoint & point)
{
	KCHMBookmarkItem * item = (KCHMBookmarkItem *) list->itemAt( point );
	
	if( item )
	{
		::mainWindow->currentBrowser()->setTabKeeper( item->m_url );
		::mainWindow->tabItemsContextMenu()->popup( list->viewport()->mapToGlobal( point ) );
	}
}
