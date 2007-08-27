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

#include <qtoolbutton.h>
#include <qcombobox.h>
#include <qlineedit.h>
#include <q3textedit.h>
#include <q3accel.h>
#include <q3popupmenu.h>
#include <qmenubar.h>
//Added by qt3to4:
#include <QPixmap>
 
#include "libchmfile.h"
#include "libchmfileimpl.h"

#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmconfig.h"
#include "kchmsearchtoolbar.h"
#include "kchmtreeviewitem.h"
#include "kchmcontentswindow.h"


KCHMSearchAndViewToolbar::KCHMSearchAndViewToolbar( KCHMMainWindow * parent )
	: QToolBar (parent)
{
}

void KCHMSearchAndViewToolbar::setEnabled( bool enable )
{
	m_findBox->setEnabled (enable);
}

void KCHMSearchAndViewToolbar::onReturnPressed( )
{
	search( true );
}

void KCHMSearchAndViewToolbar::onBtnPrevSearchResult( )
{
	search( false );
}

void KCHMSearchAndViewToolbar::onBtnNextSearchResult( )
{
	search( true );
}

void KCHMSearchAndViewToolbar::search( bool search_forward )
{
	QString searchexpr = m_findBox->lineEdit()->text();

	if ( searchexpr.isEmpty() )
		return;

	::mainWindow->currentBrowser()->searchWord( searchexpr, search_forward, false );
}

/*
void KCHMSearchAndViewToolbar::onMenuActivated( int id )
{
	const LCHMTextEncoding * enc = LCHMFileImpl::getTextEncodingTable() + id;
	::mainWindow->setTextEncoding( enc );
}

void KCHMSearchAndViewToolbar::setChosenEncodingInMenu( const LCHMTextEncoding * enc)
{
	if ( m_checkedEncodingInMenu != -1 )
		menu_enclist->setItemChecked( m_checkedEncodingInMenu, false );
	
	if ( m_checkedLanguageInMenu != -1 )
		menu_langlist->setItemChecked( m_checkedLanguageInMenu, false );
	
	int idx = LCHMFileImpl::getEncodingIndex( enc );
	if ( idx == -1 )
		return;
	
	menu_langlist->setItemChecked( idx,  true );
	m_checkedLanguageInMenu = idx;
	
	// For encoding, we need to set up charset!
	const LCHMTextEncoding * enctable = LCHMFileImpl::getTextEncodingTable();
	for ( idx = 0; (enctable + idx)->language; idx++ )
	{
		// See the next item; does is have the same charset as current?
		const LCHMTextEncoding * item = enctable + idx;
	
		// This menu is only for charsets, so we won't add duplicate charset twice
		if ( !strcmp( item->qtcodec, enc->qtcodec ) )
		{
			menu_enclist->setItemChecked ( idx, true);
			m_checkedEncodingInMenu = idx;
			break;
		}
	}
}
*/


void KCHMSearchAndViewToolbar::onAccelFocusSearchField( )
{
	m_findBox->setFocus();
}
