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

#include "kchmconfig.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmviewwindowmgr.h"

#include "kchmviewwindow_qtextbrowser.h"

#if defined (USE_KDE)
	#include "kde/kchmviewwindow_khtmlpart.h"
#endif

#if defined (QT_WEBKIT_LIB)
	#include "kchmviewwindow_qtwebkit.h"
#endif


KCHMViewWindowMgr::KCHMViewWindowMgr( QWidget *parent )
	: QWidget( parent ), Ui::TabbedBrowser()
{
	// UIC
	setupUi( this );
	
	// Remove the UIC-generated tab if it's there.
	// Do it right here before the signals are connected, since after Qt 4.4.0 it triggers 
	// the currentChanged signal.
	if ( tabWidget->count() > 0 )
		tabWidget->removeTab ( 0 );
	
	// on current tab changed
	connect( tabWidget, SIGNAL( currentChanged(QWidget *) ), this, SLOT( onTabChanged(QWidget *) ) );
	
	// Create a close button
	m_closeButton = new QToolButton( this );
	m_closeButton->setCursor( Qt::ArrowCursor );
	m_closeButton->setAutoRaise( true );
	m_closeButton->setIcon( QIcon( ":/images/closetab.png" ) );
	m_closeButton->setToolTip( i18n("Close current page") );
	m_closeButton->setEnabled( false );
	connect( m_closeButton, SIGNAL( clicked() ), this, SLOT( onCloseCurrentWindow() ) );
	
	// Put it there
	tabWidget->setCornerWidget( m_closeButton, Qt::TopRightCorner );
	
	// Create a "new tab" button
	QToolButton * newButton = new QToolButton( this );
	newButton->setCursor( Qt::ArrowCursor );
	newButton->setAutoRaise( true );
	newButton->setIcon( QIcon( ":/images/addtab.png" ) );
	newButton->setToolTip( i18n("Add page") );
	connect( newButton, SIGNAL( clicked() ), this, SLOT( openNewTab() ) );
	
	// Put it there
	tabWidget->setCornerWidget( newButton, Qt::TopLeftCorner );
	
	// Hide the search frame
	frameFind->setVisible( false );
	labelWrapped->setVisible( false );
	
	// Search Line edit
	connect( editFind,
	         SIGNAL( textEdited ( const QString & ) ),
	         this, 
	         SLOT( editTextEdited( const QString & ) ) );
	
	// Search toolbar buttons
	connect( toolClose, SIGNAL(clicked()), frameFind, SLOT( hide()) );
	connect( toolPrevious, SIGNAL(clicked()), this, SLOT( onFindPrevious()) );
	connect( toolNext, SIGNAL(clicked()), this, SLOT( onFindNext()) );
}

KCHMViewWindowMgr::~KCHMViewWindowMgr( )
{
}
	
void KCHMViewWindowMgr::createMenu( KCHMMainWindow *, QMenu * menuWindow, QAction * actionCloseWindow )
{
	m_menuWindow = menuWindow;
	m_actionCloseWindow = actionCloseWindow; 
}

void KCHMViewWindowMgr::invalidate()
{
	closeAllWindows();
	addNewTab( true );
}


KCHMViewWindow * KCHMViewWindowMgr::current()
{
	TabData * tab = findTab( tabWidget->currentWidget() );
	
	if ( !tab )
		abort();
	
	return tab->window;
}

KCHMViewWindow * KCHMViewWindowMgr::addNewTab( bool set_active )
{
	KCHMViewWindow * viewvnd;
	
	switch ( appConfig.m_usedBrowser )
	{
		default:
			viewvnd = new KCHMViewWindow_QTextBrowser( tabWidget );
			break;

#if defined (USE_KDE)			
		case KCHMConfig::BROWSER_KHTMLPART:
			viewvnd = new KCHMViewWindow_KHTMLPart( tabWidget );
			break;
#endif			
			
#if defined (QT_WEBKIT_LIB)
		case KCHMConfig::BROWSER_QTWEBKIT:
			viewvnd = new KCHMViewWindow_QtWebKit( tabWidget );
			break;
#endif			
	}
	
	editFind->installEventFilter( this );
	
	// Create the tab data structure
	TabData tabdata;
	tabdata.window = viewvnd;
	tabdata.action = new QAction( "window", this ); // temporary name; real name is set in setTabName
	tabdata.widget = viewvnd->getQWidget();
	
	connect( tabdata.action,
			 SIGNAL( triggered() ),
	         this,
	         SLOT( activateWindow() ) );
	
	m_Windows.push_back( tabdata );
	tabWidget->addTab( tabdata.widget, "" );	
	Q_ASSERT( m_Windows.size() == tabWidget->count() );
		
	// Set active if it is the first tab
	if ( set_active || m_Windows.size() == 1 )
		tabWidget->setCurrentWidget( tabdata.widget );
	
	// Handle clicking on link in browser window
	connect( viewvnd->getQObject(), 
	         SIGNAL( linkClicked (const QString &, bool &) ), 
	         ::mainWindow, 
	         SLOT( activateLink(const QString &, bool &) ) );
	
	// Set up the accelerator if we have room
	if ( m_Windows.size() < 10 )
		tabdata.action->setShortcut( QKeySequence( i18n("Alt+%1").arg( m_Windows.size() ) ) );
	
	// Add it to the "Windows" menu
	m_menuWindow->addAction( tabdata.action );
	
	return viewvnd;
}

void KCHMViewWindowMgr::closeAllWindows( )
{
	// No it++ - we removing the window by every closeWindow call
	while ( m_Windows.begin() != m_Windows.end() )
		closeWindow( m_Windows.first().widget );
}

void KCHMViewWindowMgr::setTabName( KCHMViewWindow * window )
{
	TabData * tab = findTab( window->getQWidget() );
	
	if ( tab )
	{
		QString title = window->getTitle();
		
		// Trim too long string
		if ( title.length() > 25 )
			title = title.left( 22 ) + "...";
	
		tabWidget->setTabText( tabWidget->indexOf( window->getQWidget() ), title );
		tab->action->setText( title );
		
		updateCloseButtons();
	}
}

void KCHMViewWindowMgr::onCloseCurrentWindow( )
{
	// Do not allow to close the last window
	if ( m_Windows.size() == 1 )
		return;
			
	TabData * tab = findTab( tabWidget->currentWidget() );
	closeWindow( tab->widget );
}

void KCHMViewWindowMgr::closeWindow( QWidget * widget )
{
	WindowsIterator it;
	
	for ( it = m_Windows.begin(); it != m_Windows.end(); ++it )
		if ( it->widget == widget )
			break;
	
	if ( it == m_Windows.end() )
		qFatal( "KCHMViewWindowMgr::closeWindow called with unknown widget!" );

	m_menuWindow->removeAction( it->action );
	
	tabWidget->removeTab( tabWidget->indexOf( it->widget ) );
	delete it->window;
	delete it->action;
	
	m_Windows.erase( it );
	updateCloseButtons();
	
	// Change the accelerators, as we might have removed the item in the middle
	int count = 1;
	for ( WindowsIterator it = m_Windows.begin(); it != m_Windows.end() && count < 10; ++it, count++ )
		(*it).action->setShortcut( QKeySequence( i18n("Alt+%1").arg( count ) ) );
}


void KCHMViewWindowMgr::restoreSettings( const KCHMSettings::viewindow_saved_settings_t & settings )
{
	// Destroy automatically created tab
	closeWindow( m_Windows.first().widget );
	
	for ( int i = 0; i < settings.size(); i++ )
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
	
	for ( int i = 0; i < tabWidget->count(); i++ )
	{
		QWidget * p = tabWidget->widget( i );
		TabData * tab = findTab( p );
			
		if ( !tab )
			abort();
		
		settings.push_back( 
		                    KCHMSettings::SavedViewWindow( 
			                    tab->window->getOpenedPage(), 
			                    tab->window->getScrollbarPosition(), 
			                    tab->window->getZoomFactor()) );
	}
}

void KCHMViewWindowMgr::updateCloseButtons( )
{
	bool enabled = m_Windows.size() > 1;
	
	m_actionCloseWindow->setEnabled( enabled );
	m_closeButton->setEnabled( enabled );
}

void KCHMViewWindowMgr::onTabChanged( QWidget * newtab )
{
	TabData * tab = findTab( newtab );
	
	if ( tab )
	{
		tab->window->updateNavigationToolbar();
		mainWindow->browserChanged( tab->window );
		tab->widget->setFocus();
	}
}


void KCHMViewWindowMgr::openNewTab()
{
	::mainWindow->openPage( current()->getOpenedPage(), 
	                        KCHMMainWindow::OPF_NEW_TAB | KCHMMainWindow::OPF_CONTENT_TREE | KCHMMainWindow::OPF_ADD2HISTORY );
}

void KCHMViewWindowMgr::activateWindow()
{
	QAction *action = qobject_cast< QAction * >(sender());
	
	for ( WindowsIterator it = m_Windows.begin(); it != m_Windows.end(); ++it )
	{
		if ( it->action != action )
			continue;
		
		QWidget *widget = it->widget;
		tabWidget->setCurrentWidget(widget);
		break;
	}
}

KCHMViewWindowMgr::TabData * KCHMViewWindowMgr::findTab(QWidget * widget)
{
	for ( WindowsIterator it = m_Windows.begin(); it != m_Windows.end(); ++it )
		if ( it->widget == widget )
			return (it.operator->());
		
	return 0;
}

void KCHMViewWindowMgr::setCurrentPage(int index)
{
	tabWidget->setCurrentIndex( index );
}

int KCHMViewWindowMgr::currentPageIndex() const
{
	return tabWidget->currentIndex();
}


void KCHMViewWindowMgr::indicateFindResultStatus( SearchResultStatus status )
{
	QPalette p = editFind->palette();
	
	if ( status == SearchResultNotFound )
		p.setColor( QPalette::Active, QPalette::Base, QColor(255, 102, 102) );
	else
		p.setColor( QPalette::Active, QPalette::Base, Qt::white );
	
	editFind->setPalette( p );
	labelWrapped->setVisible( status == SearchResultFoundWrapped );
}


void KCHMViewWindowMgr::onActivateFind()
{
	frameFind->show();
	labelWrapped->setVisible( false );
	editFind->setFocus( Qt::ShortcutFocusReason );
	editFind->selectAll();
}


void KCHMViewWindowMgr::find()
{
	int flags = 0;
	
	if ( checkCase->isChecked() )
		flags |= KCHMViewWindow::SEARCH_CASESENSITIVE;
	
	if ( checkWholeWords->isChecked() )
		flags |= KCHMViewWindow::SEARCH_WHOLEWORDS;

	current()->find( editFind->text(), flags );
		
	if ( !frameFind->isVisible() )
		frameFind->show();
}


void KCHMViewWindowMgr::editTextEdited(const QString &)
{
	find();
}

void KCHMViewWindowMgr::onFindNext()
{
	current()->onFindNext();
}

void KCHMViewWindowMgr::onFindPrevious()
{
	current()->onFindPrevious();
}
