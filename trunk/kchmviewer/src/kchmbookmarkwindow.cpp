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

#include "kchmbookmarkwindow.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "xchmfile.h"

KCHMBookmarkWindow::KCHMBookmarkWindow(QWidget *parent, const char *name)
 : QWidget(parent, name)
{
	QVBoxLayout * layout = new QVBoxLayout (this);
	layout->setMargin (5);

	m_bookmarkList = new QListView (this);
	m_bookmarkList->addColumn( "bookmark" ); // no need to i18n - the column is hidden
	m_bookmarkList->header()->hide();
	layout->addWidget (m_bookmarkList);

	QHBoxLayout * hlayout = new QHBoxLayout (layout);
	QPushButton * add = new QPushButton ( i18n( "&Add" ), this);
	QPushButton * edit = new QPushButton ( i18n( "&Edit" ), this);
	QPushButton * del = new QPushButton ( i18n( "&Del" ), this);
	
	hlayout->addWidget (add);
	hlayout->addWidget (edit);
	hlayout->addWidget (del);
	
	//layout->addLayout (hlayout);

	connect( m_bookmarkList, SIGNAL( doubleClicked ( QListViewItem *, const QPoint &, int) ), this, SLOT( onDoubleClicked ( QListViewItem *, const QPoint &, int) ) );
	
	connect( add, SIGNAL( clicked () ), this, SLOT( onAddBookmarkPressed( ) ) );
	connect( del, SIGNAL( clicked () ), this, SLOT( onDelBookmarkPressed( ) ) );
	connect( edit, SIGNAL( clicked () ), this, SLOT( onEditBookmarkPressed( ) ) );

	m_listChanged = false;
}

void KCHMBookmarkWindow::onAddBookmarkPressed( )
{
    bool ok;
	QString url = ::mainWindow->getCurrentBrowser()->getOpenedPage();
	QString title = ::mainWindow->getChmFile()->getTopicByUrl(url);
	QString name = QInputDialog::getText( 
			i18n( "%1 - add a bookmark") . arg(APP_NAME),
			i18n( "Enter the name for this bookmark:" ),
			QLineEdit::Normal,
			title,
			&ok, 
			this);
    
	if ( !ok || name.isEmpty() )
		return;

	new KCMBookmarkTreeViewItem (m_bookmarkList, name, url, ::mainWindow->getCurrentBrowser()->getScrollbarPosition()
);
	m_listChanged = true;
}


void KCHMBookmarkWindow::onDelBookmarkPressed( )
{
	KCMBookmarkTreeViewItem * item = (KCMBookmarkTreeViewItem *) m_bookmarkList->selectedItem();
	
	if ( item )
	{
		delete item;
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::onEditBookmarkPressed( )
{
	KCMBookmarkTreeViewItem * item = (KCMBookmarkTreeViewItem *) m_bookmarkList->selectedItem();
	
	if ( item )
	{
	    bool ok;
		QString name = QInputDialog::getText( 
			i18n( "%1 - edit the bookmark name") . arg(APP_NAME),
			i18n( "Enter the name for this bookmark:" ),
			QLineEdit::Normal,
			item->m_name, 
			&ok, 
			this);
    
		if ( !ok || name.isEmpty() )
			return;

		item->setText (0, name);
		m_listChanged = true;
	}
}


void KCHMBookmarkWindow::onDoubleClicked( QListViewItem * item, const QPoint &, int )
{
	if ( !item )
		return;
	
	KCMBookmarkTreeViewItem * treeitem = (KCMBookmarkTreeViewItem *) item;
	
	if ( ::mainWindow->getCurrentBrowser()->getOpenedPage() != treeitem->m_url )
		::mainWindow->openPage( treeitem->m_url, OPF_CONTENT_TREE | OPF_ADD2HISTORY );
	
	::mainWindow->getCurrentBrowser()->setScrollbarPosition(treeitem->m_scroll_y);
}


void KCHMBookmarkWindow::restoreSettings( const KCHMSettings::bookmark_saved_settings_t & settings )
{
	for ( unsigned int i = 0; i < settings.size(); i++ )
		new KCMBookmarkTreeViewItem (m_bookmarkList, settings[i].name, settings[i].url, settings[i].scroll_y);
}


void KCHMBookmarkWindow::saveSettings( KCHMSettings::bookmark_saved_settings_t & settings )
{
    QListViewItemIterator it (m_bookmarkList);

	settings.clear();

	for ( ; it.current(); it++ )
	{
		KCMBookmarkTreeViewItem * treeitem = (KCMBookmarkTreeViewItem *) it.current();
		settings.push_back (KCHMSettings::SavedBookmark(treeitem->m_name, treeitem->m_url, treeitem->m_scroll_y));
    }
}

void KCHMBookmarkWindow::invalidate( )
{
	m_bookmarkList->clear();
}

#include "kchmbookmarkwindow.moc"
