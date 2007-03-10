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

#include <qaccel.h>

#include "kchmconfig.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmviewwindowmgr.h"
#include "iconstorage.h"

#include "kchmviewwindow_qtextbrowser.h"

#if defined (USE_KDE)
	#include "kchmviewwindow_khtmlpart.h"
#endif


KCHMViewWindowMgr::KCHMViewWindowMgr( QWidget *parent )
	: QTabWidget( parent ) //QTabWidget
{
	m_MenuWindow = 0;
	
	// on current tab changed
	connect( this, SIGNAL( currentChanged(QWidget *) ), this, SLOT( onTabChanged(QWidget *) ) );
	
	// Create an iconset for the button
	QIconSet iset( *gIconStorage.getCloseWindowIcon() );
	
	// Create a pushbutton
	m_closeButton = new QPushButton( iset, QString::null, this );
	m_closeButton->setFlat( true );
	m_closeButton->setEnabled( false );
	connect( m_closeButton, SIGNAL( clicked() ), this, SLOT( closeCurrentWindow() ) );
	
	setCornerWidget( m_closeButton, TopRight);
}

KCHMViewWindowMgr::~KCHMViewWindowMgr( )
{
}
	
void KCHMViewWindowMgr::createMenu( KCHMMainWindow * parent )
{
	// Create the approptiate menu entries in 'View' main menu
	m_MenuWindow = new KQPopupMenu( parent );
	parent->menuBar()->insertItem( i18n( "&Window"), m_MenuWindow );

	m_menuIdClose = m_MenuWindow->insertItem( i18n( "&Close"), this, SLOT( closeCurrentWindow()), CTRL+Key_W );
	m_MenuWindow->insertSeparator();

	//connect( m_MenuWindow, SIGNAL( activated(int) ), this, SLOT ( onCloseWindow(int) ));
	connect( m_MenuWindow, SIGNAL( activated(int) ), this, SLOT ( onActiveWindow(int) ));
}

void KCHMViewWindowMgr::invalidate()
{
	deleteAllWindows();
	addNewTab( true );
}


KCHMViewWindow * KCHMViewWindowMgr::current()
{
	QWidget * w = currentPage();
	WindowsIterator it;
			
	if ( !w || (it = m_Windows.find( w )) == m_Windows.end() )
		qFatal( "KCHMViewWindowMgr::current called without any windows!" );
	
	return it.data().window;
}

KCHMViewWindow * KCHMViewWindowMgr::addNewTab( bool set_active )
{
	KCHMViewWindow * viewvnd;
	
#if defined (USE_KDE)
	if ( !appConfig.m_kdeUseQTextBrowser )
		viewvnd = new KCHMViewWindow_KHTMLPart( this );
	else
#endif
		viewvnd = new KCHMViewWindow_QTextBrowser( this );

	QWidget * widget = viewvnd->getQWidget();
	m_Windows[widget].window = viewvnd;
	m_Windows[widget].menuitem = 0;
	m_Windows[widget].widget = widget;
	
	addTab( widget, "" );

	Q_ASSERT( m_Windows.size() == (unsigned int) count() );
		
	// Set active if it is the first tab
	if ( set_active || m_Windows.size() == 1 )
		showPage( widget );
	
	// Handle clicking on link in browser window
	connect( viewvnd->getQObject(), SIGNAL( signalLinkClicked (const QString &, bool &) ), ::mainWindow, SLOT( slotLinkClicked(const QString &, bool &) ) );
	
	return viewvnd;
}

void KCHMViewWindowMgr::deleteAllWindows( )
{
	// No it++ - we removing the window by every closeWindow call
	while ( m_Windows.begin() != m_Windows.end() )
		closeWindow( m_Windows.begin().data() );
}

void KCHMViewWindowMgr::setTabName( KCHMViewWindow * window )
{
	WindowsIterator it = m_Windows.find( window->getQWidget() );
			
	if ( it == m_Windows.end() )
		qFatal( "KCHMViewWindowMgr::setTabName called with unknown window!" );
	
	QString title = window->getTitle();
	
	// Trim too long string
	if ( title.length() > 25 )
		title = title.left( 22 ) + "...";

	setTabLabel( window->getQWidget(), title );
	
	if ( it.data().menuitem == 0 )
	{
		// find the empty menuid
		int menuid;
		
		if ( !m_idSlot.empty() )
		{
			menuid = *m_idSlot.begin();
			m_idSlot.erase( m_idSlot.begin() );
		}
		else
			menuid = m_Windows.size();

		QString menutitle = "&" + QString::number(menuid) + " " + title;
		it.data().menuitem = menuid;
		m_MenuWindow->insertItem(menutitle, menuid);
		updateTabAccel();
	}
	else
	{
		QString menutitle = "&" + QString::number(it.data().menuitem) + " " + title;
		m_MenuWindow->changeItem( it.data().menuitem, menutitle );
	}
	
	updateCloseButtons();
}

void KCHMViewWindowMgr::closeCurrentWindow( )
{
	// Do not allow to close the last window
	if ( m_Windows.size() == 1 )
		return;
			
	QWidget * w = currentPage();
	WindowsIterator it;
			
	if ( !w || (it = m_Windows.find( w )) == m_Windows.end() )
		qFatal( "KCHMViewWindowMgr::closeCurrentWindow called without any windows!" );
	
	closeWindow( it.data() );
}

void KCHMViewWindowMgr::closeWindow( const tab_window_t & tab )
{
	WindowsIterator it = m_Windows.find( tab.widget );
			
	if ( it == m_Windows.end() )
		qFatal( "KCHMViewWindowMgr::closeWindow called with unknown widget!" );

	if ( tab.menuitem != 0 )
	{
		m_MenuWindow->removeItem( tab.menuitem );
		m_idSlot.push_back( tab.menuitem );
	}
	
	removePage( tab.widget );
	delete tab.window;
	
	m_Windows.remove( it );
	updateCloseButtons();
	updateTabAccel();
}

void KCHMViewWindowMgr::onCloseWindow( int id )
{
	for ( WindowsIterator it = m_Windows.begin(); it != m_Windows.end(); it++ )
	{
		if ( it.data().menuitem != id )
			continue;
		
		closeWindow( it.data() );
		break;
	}
}


void KCHMViewWindowMgr::onActiveWindow(int id)
{
	for (WindowsIterator it = m_Windows.begin(); it != m_Windows.end(); ++it)
	{
		if ( it.data().menuitem != id )
			continue;
		
		QWidget *widget = it.data().widget;
		showPage(widget);
		break;
	}
}


void KCHMViewWindowMgr::restoreSettings( const KCHMSettings::viewindow_saved_settings_t & settings )
{
	// Destroy pre-created tab
	closeWindow( m_Windows.begin().data() );
	
	for ( unsigned int i = 0; i < settings.size(); i++ )
	{
		KCHMViewWindow * window = addNewTab( false );
		window->openUrl( settings[i].url ); // will call setTabName()
		window->setScrollbarPosition( settings[i].scroll_y );
		window->setZoomFactor( settings[i].zoom );
	}
}


void KCHMViewWindowMgr::saveSettings( KCHMSettings::viewindow_saved_settings_t & settings )
{
	settings.clear();
	
	for ( int i = 0; i < count(); i++ )
	{
		QWidget * p = page( i );
		WindowsIterator it = m_Windows.find( p );
			
		if ( it == m_Windows.end() )
			qFatal( "KCHMViewWindowMgr::saveSettings: could not find widget!" );

		settings.push_back( 
				KCHMSettings::SavedViewWindow( 
						it.data().window->getOpenedPage(), 
						it.data().window->getScrollbarPosition(), 
						it.data().window->getZoomFactor()) );
	}
}

void KCHMViewWindowMgr::updateCloseButtons( )
{
	m_MenuWindow->setItemEnabled( m_menuIdClose, m_Windows.size() > 1 );
	m_closeButton->setEnabled( m_Windows.size() > 1 );
}

void KCHMViewWindowMgr::onTabChanged( QWidget * newtab )
{
	WindowsIterator it = m_Windows.find( newtab );
			
	if ( it == m_Windows.end() )
		qFatal( "KCHMViewWindowMgr::onTabChanged called with unknown widget!" );

	it.data().window->updateNavigationToolbar();
	mainWindow->slotBrowserChanged( it.data().window );
}


void KCHMViewWindowMgr::updateTabAccel()
{
	WindowsIterator it;
    for ( it = m_Windows.begin(); it != m_Windows.end(); ++it )
	{
		int menuid = it.data().menuitem;
		int index = indexOf(it.data().widget);
		
		if ( index <= 9 )
		{
			if ( index < 9 )
				index++;
			else
				index = 0;
			
			m_MenuWindow->setAccel(ALT + key(index), menuid);
		}
	}
}

QKeySequence KCHMViewWindowMgr::key(int i)
{
	switch (i)
	{
		case 0:
			return Key_0;
			
		case 1:
			return Key_1;
			
		case 2:
			return Key_2;
			
		case 3:
			return Key_3;
			
		case 4:
			return Key_4;
			
		case 5:
			return Key_5;
			
		case 6:
			return Key_6;
			
		case 7:
			return Key_7;
			
		case 8:
			return Key_8;
			
		default:
			return Key_9;
	}
}


#include "kchmviewwindowmgr.moc"
