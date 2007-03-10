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

#include "kde-qt.h"
#include "kchmnavtoolbar.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "iconstorage.h"


KCHMNavToolbar::KCHMNavToolbar( KCHMMainWindow *parent )
	: QToolBar( parent )
{
	// Initialize toolbar
	setLabel( i18n( "Navigation") );
	
	QPixmap iconBackward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::back));
	m_toolbarIconBackward = new QToolButton (iconBackward,
											 i18n( "Move backward in history"),
											 QString::null,
											 parent,
											 SLOT( slotNavigateBack() ),
											 this);
	QWhatsThis::add( m_toolbarIconBackward, i18n( "Click this button to move backward in browser history") );	

	QPixmap iconForward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::forward));
	m_toolbarIconForward = new QToolButton (iconForward,
											i18n( "Move forward in history"),
											QString::null,
											parent,
											SLOT( slotNavigateForward() ),
											this);
	QWhatsThis::add( m_toolbarIconForward, i18n( "Click this button to move forward in browser history") );	
	
	QPixmap iconHome = (*gIconStorage.getToolbarPixmap(KCHMIconStorage::gohome));
	QToolButton	* hb = new QToolButton (iconHome,
					 i18n( "Go to the home page"),
					 QString::null,
					 parent,
					 SLOT( slotNavigateHome() ),
					 this);
	QWhatsThis::add( hb, i18n( "Click this button to move to the home page") );	
}


KCHMNavToolbar::~KCHMNavToolbar()
{
}

void KCHMNavToolbar::updateIconStatus( bool enable_backward, bool enable_forward )
{
	m_toolbarIconBackward->setEnabled( enable_backward );
	m_toolbarIconForward->setEnabled ( enable_forward );
}


#include "kchmnavtoolbar.moc"
