
/***************************************************************************
 *   Copyright (C) 2005 by Georgy Yunaev                                   *
 *   tim@krasnogorsk.ru                                                    *
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

#include <qtoolbutton.h>
#include <qcombobox.h>
#include <qlineedit.h>
#include <qtextedit.h>
#include <qpopupmenu.h>
#include <qmenubar.h>
 
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmconfig.h"
#include "kchmsearchtoolbar.h"

#include "iconstorage.h"

static QPopupMenu * menu_enclist;

KCHMSearchAndViewToolbar::KCHMSearchAndViewToolbar( KCHMMainWindow * parent )
	: QToolBar (parent)
{
	int menuid;
	setLabel( tr("Find in page") );

    QPixmap iconPrev (*gIconStorage.getToolbarPixmap(KCHMIconStorage::findprev));
    QPixmap iconNext (*gIconStorage.getToolbarPixmap(KCHMIconStorage::findnext));
    QPixmap iconFontInc (*gIconStorage.getToolbarPixmap(KCHMIconStorage::view_increase));
    QPixmap iconFontDec (*gIconStorage.getToolbarPixmap(KCHMIconStorage::view_decrease));
    QPixmap iconViewSource (*gIconStorage.getToolbarPixmap(KCHMIconStorage::viewsource));
    QPixmap iconAddBookmark (*gIconStorage.getToolbarPixmap(KCHMIconStorage::bookmark_add));
	
	m_findBox = new QComboBox (TRUE, this);
	m_findBox->setMinimumWidth (200);
	connect( m_findBox->lineEdit(), SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	connect( m_findBox->lineEdit(), SIGNAL( textChanged (const QString &) ), this, SLOT( onTextChanged(const QString &) ) );
	
	m_buttonPrev = new QToolButton (iconPrev,
				tr("Previous result"),
				QString::null,
				this,
				SLOT(onBtnPrev()),
				this);

	m_buttonNext = new QToolButton (iconNext,
				tr("Next result"),
				QString::null,
				this,
				SLOT(onBtnNext()),
				this);
	
	m_buttonFontInc = new QToolButton (iconFontInc,
				tr("Increase font"),
				QString::null,
				this,
				SLOT(onBtnFontInc()),
				this);

	m_buttonFontDec = new QToolButton (iconFontDec,
				tr("Decrease font"),
				QString::null,
				this,
				SLOT(onBtnFontDec()),
				this);

	m_buttonViewSource = new QToolButton (iconViewSource,
				tr("View HTML source"),
				QString::null,
				this,
				SLOT(onBtnViewSource()),
				this);

	m_buttonAddBookmark = new QToolButton (iconAddBookmark,
				tr("Add to bookmarks"),
				QString::null,
				this,
				SLOT(onBtnAddBookmark()),
				this);

	cleanSearch();
	
    QPopupMenu * menu_view = new QPopupMenu( parent );
    parent->menuBar()->insertItem( tr("&View"), menu_view );

	menu_view->insertItem( tr("&Increase font"), this, SLOT(onBtnFontInc()), Key_Plus );
	menu_view->insertItem( tr("&Decrease font"), this, SLOT(onBtnFontDec()), Key_Minus );
	menu_view->insertItem( tr("&View HTML source"), this, SLOT(onBtnViewSource()) );
	
    menu_view->insertSeparator();
	menu_view->insertItem( tr("&Bookmark this page"), this, SLOT(onBtnAddBookmark()) );
    menu_view->insertSeparator();
	
	// Prepare the encoding list
    menu_enclist = new QPopupMenu( parent );
	QPopupMenu * menu_sublang = 0;
	
	connect (menu_enclist, SIGNAL( activated(int) ), this, SLOT ( onMenuActivated(int) ));
	
	for ( const KCHMTextEncoding::text_encoding_t * item = KCHMTextEncoding::getTextEncoding(); 
			item->charset; item++ )
	{
		// See the next item; does is have the same charset as current?
		const KCHMTextEncoding::text_encoding_t * nextitem = item  + 1;
		
		if ( nextitem->charset )
		{
			if ( !strcmp (item->charset, nextitem->charset) )
			{
				// If charset is the same as next one, create a new popup menu.
				// If the menu is already created, add to it
				if ( !menu_sublang )
				{
					menu_sublang = new QPopupMenu( menu_enclist );
					connect (menu_sublang, SIGNAL( activated(int) ), this, SLOT ( onMenuActivated(int) ));
				}
					
				menuid = menu_sublang->insertItem( item->country, (int) item );
//				m_mapMenuId2Encoding[menuid] = item;
				continue;
			}
		}
		
		// If the next charset differs from this one,
		// add a submenu if menu_sublang is already created.
		// otherwise, just add an item
		if ( menu_sublang )
		{
			menu_sublang->insertItem( item->country );
			menuid = menu_enclist->insertItem( item->charset, menu_sublang, (int) item );
			menu_sublang = 0;
		}
		else
			menuid = menu_enclist->insertItem( item->charset, (int) item );
			
		//m_mapMenuId2Encoding[menuid] = item;
	}
    
	menu_view->insertItem( tr("&Set encoding"), menu_enclist );
	m_checkedEncodingInMenu = 0;
}

void KCHMSearchAndViewToolbar::setEnabled( bool enable )
{
	m_findBox->setEnabled (enable);
	m_buttonPrev->setEnabled (enable);
	m_buttonNext->setEnabled (enable);
	m_buttonFontInc->setEnabled (enable);
	m_buttonFontDec->setEnabled (enable);
	m_buttonViewSource->setEnabled (enable);
	m_buttonAddBookmark->setEnabled (enable);
}

void KCHMSearchAndViewToolbar::onReturnPressed( )
{
	search( true );
}

void KCHMSearchAndViewToolbar::onBtnPrev( )
{
	search( false );
}

void KCHMSearchAndViewToolbar::onBtnNext( )
{
	search( true );
}

void KCHMSearchAndViewToolbar::cleanSearch( )
{
	last_index = 0;
	last_paragraph = 0;
}

void KCHMSearchAndViewToolbar::search( bool search_forward )
{
	if ( m_searchexpr.isEmpty() )
	{
		m_searchexpr = m_findBox->lineEdit()->text();

		if ( m_searchexpr.isEmpty() )
			return;
	}
	
	if ( search_forward && (last_index || last_paragraph) )
		last_index += m_searchexpr.length();

	if ( !::mainWindow->getViewWindow()->find (m_searchexpr, false, false, search_forward, &last_paragraph, &last_index) )
		::mainWindow->showInStatusBar ( tr("Search failed"));
	else
	{
		::mainWindow->showInStatusBar ( tr("Found at paragraph %1, offset %1") . arg(last_paragraph)  . arg(last_index) );
	}
}

void KCHMSearchAndViewToolbar::onTextChanged( const QString & )
{
	m_searchexpr = QString::null;
	cleanSearch();
}

void KCHMSearchAndViewToolbar::onBtnFontInc( )
{
	emit ::mainWindow->getViewWindow()->zoomIn();
}

void KCHMSearchAndViewToolbar::onBtnFontDec( )
{
	emit ::mainWindow->getViewWindow()->zoomOut();
}

void KCHMSearchAndViewToolbar::onBtnViewSource( )
{
	QTextEdit * editor = new QTextEdit (0);
	editor->setTextFormat ( Qt::PlainText );
	editor->setText (::mainWindow->getViewWindow()->text());
	editor->setCaption ( QString(APP_NAME) + " - view HTML source of " + ::mainWindow->getViewWindow()->getOpenedPage() );
	editor->resize (800, 600);
	editor->show();
}

void KCHMSearchAndViewToolbar::onBtnAddBookmark( )
{
	emit ::mainWindow->addBookmark();
}

void KCHMSearchAndViewToolbar::onMenuActivated( int id )
{
	const KCHMTextEncoding::text_encoding_t * enc = (const KCHMTextEncoding::text_encoding_t *) id;
	::mainWindow->setTextEncoding (enc);
}

void KCHMSearchAndViewToolbar::setChosenEncodingInMenu( const KCHMTextEncoding::text_encoding_t * enc)
{
	if ( m_checkedEncodingInMenu )
		menu_enclist->setItemChecked ((int)m_checkedEncodingInMenu, false);
	
	menu_enclist->setItemChecked ((int)enc, true);
	m_checkedEncodingInMenu = enc;
}
