
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
#include "xchmfile.h"

#include "iconstorage.h"

static KQPopupMenu * menu_enclist;

KCHMSearchAndViewToolbar::KCHMSearchAndViewToolbar( KCHMMainWindow * parent )
	: QToolBar (parent)
{
	int menuid;
	
	// Toolbar label
	setLabel( tr("Find in page") );

	// Load the pixmaps
    QPixmap iconPrev (*gIconStorage.getToolbarPixmap(KCHMIconStorage::findprev));
    QPixmap iconNext (*gIconStorage.getToolbarPixmap(KCHMIconStorage::findnext));
    QPixmap iconFontInc (*gIconStorage.getToolbarPixmap(KCHMIconStorage::view_increase));
    QPixmap iconFontDec (*gIconStorage.getToolbarPixmap(KCHMIconStorage::view_decrease));
    QPixmap iconViewSource (*gIconStorage.getToolbarPixmap(KCHMIconStorage::viewsource));
    QPixmap iconAddBookmark (*gIconStorage.getToolbarPixmap(KCHMIconStorage::bookmark_add));

	QWhatsThis::whatsThisButton( this );

	// Create the combobox to enter the find text
	m_findBox = new QComboBox (TRUE, this);
	m_findBox->setMinimumWidth (200);
	connect( m_findBox->lineEdit(), SIGNAL( returnPressed() ), this, SLOT( onReturnPressed() ) );
	
	QWhatsThis::add( m_findBox, tr("Enter here the text to search in the current page.") );	
	
	// Button 'prevous search result'
	m_buttonPrev = new QToolButton (iconPrev,
				tr("Previous search result"),
				QString::null,
				this,
				SLOT(onBtnPrev()),
				this);
	QWhatsThis::add( m_buttonPrev, tr("Click this button to find previous search result.") );

	// Button 'next search result'
	m_buttonNext = new QToolButton (iconNext,
				tr("Next search result"),
				QString::null,
				this,
				SLOT(onBtnNext()),
				this);
	QWhatsThis::add( m_buttonNext, tr("Click this button to find next search result.") );

	// Button 'increase font size'
	m_buttonFontInc = new QToolButton (iconFontInc,
				tr("Increase font size"),
				QString::null,
				this,
				SLOT(onBtnFontInc()),
				this);
	QWhatsThis::add( m_buttonFontInc, tr("Click this button to increase the font size.") );

	// Button 'decrease font size'
	m_buttonFontDec = new QToolButton (iconFontDec,
				tr("Decrease font size"),
				QString::null,
				this,
				SLOT(onBtnFontDec()),
				this);
	QWhatsThis::add( m_buttonFontDec, tr("Click this button to decrease the font size.") );
	
	// Button 'view HTML source'
	m_buttonViewSource = new QToolButton (iconViewSource,
				tr("View HTML source"),
				QString::null,
				this,
				SLOT(onBtnViewSource()),
				this);
	QWhatsThis::add( m_buttonViewSource, tr("Click this button to open a separate window with the page HTML source.") );
	
	// Button 'add a bookmark'
	m_buttonAddBookmark = new QToolButton (iconAddBookmark,
				tr("Add to bookmarks"),
				QString::null,
				this,
				SLOT(onBtnAddBookmark()),
				this);
	QWhatsThis::add( m_buttonAddBookmark, tr("Click this button to add the current page to the bookmarks list.") );
	
	// Create the approptiate menu entries in 'View' main menu
	KQPopupMenu * menu_view = new KQPopupMenu( parent );
    parent->menuBar()->insertItem( tr("&View"), menu_view );

	menu_view->insertItem( tr("&Increase font"), this, SLOT(onBtnFontInc()), Key_Plus );
	menu_view->insertItem( tr("&Decrease font"), this, SLOT(onBtnFontDec()), Key_Minus );
	menu_view->insertItem( tr("&View HTML source"), this, SLOT(onBtnViewSource()) );
	
    menu_view->insertSeparator();
	menu_view->insertItem( tr("&Bookmark this page"), this, SLOT(onBtnAddBookmark()) );
    menu_view->insertSeparator();
	
	// Prepare the encodings menu.
    menu_enclist = new KQPopupMenu( parent );
	KQPopupMenu * menu_sublang = 0;

	// Because the encoding menu is very large, it is not reasonable to have a slot for every item.
	// It is simplier just to use a single slot for any menu item of this submenu.
	connect (menu_enclist, SIGNAL( activated(int) ), this, SLOT ( onMenuActivated(int) ));
	
	// Add the language entries
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
					menu_sublang = new KQPopupMenu( menu_enclist );
					connect (menu_sublang, SIGNAL( activated(int) ), this, SLOT ( onMenuActivated(int) ));
				}
					
				menuid = menu_sublang->insertItem( item->country, (int) item );
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

void KCHMSearchAndViewToolbar::search( bool search_forward )
{
	QString searchexpr = m_findBox->lineEdit()->text();

	if ( searchexpr.isEmpty() )
		return;

	::mainWindow->getViewWindow()->searchWord( searchexpr, search_forward, false );
}

void KCHMSearchAndViewToolbar::onBtnFontInc( )
{
	::mainWindow->getViewWindow()->addZoomFactor(1);
}

void KCHMSearchAndViewToolbar::onBtnFontDec( )
{
	::mainWindow->getViewWindow()->addZoomFactor(-1);
}

void KCHMSearchAndViewToolbar::onBtnViewSource( )
{
	QTextEdit * editor = new QTextEdit (::mainWindow);
	editor->setTextFormat ( Qt::PlainText );

	QString text;

	if ( !::mainWindow->getChmFile()->GetFileContentAsString (text, ::mainWindow->getViewWindow()->getOpenedPage()) )
		return;

	editor->setText (text);
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