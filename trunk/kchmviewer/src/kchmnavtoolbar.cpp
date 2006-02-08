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

#include "kde-qt.h"
#include "kchmnavtoolbar.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "iconstorage.h"
#include "xchmfile.h"


KCHMNavToolbar::KCHMNavToolbar( KCHMMainWindow *parent )
	: QToolBar( parent )
{
	// Initialize toolbar
	setLabel( i18n( "Navigation") );
	
	QPixmap iconBackward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::back));
	m_toolbarIconBackward = new QToolButton (iconBackward,
											 i18n( "Move backward in history"),
											 QString::null,
											 this,
											 SLOT( navigateBack() ),
											 this);
	QWhatsThis::add( m_toolbarIconBackward, i18n( "Click this button to move backward in browser history") );	

	QPixmap iconForward (*gIconStorage.getToolbarPixmap(KCHMIconStorage::forward));
	m_toolbarIconForward = new QToolButton (iconForward,
											i18n( "Move forward in history"),
											QString::null,
											this,
											SLOT( navigateForward() ),
											this);
	QWhatsThis::add( m_toolbarIconBackward, i18n( "Click this button to move forward in browser history") );	
	
	QPixmap iconHome = (*gIconStorage.getToolbarPixmap(KCHMIconStorage::gohome));
	new QToolButton (iconHome,
					 i18n( "Go to the home page"),
					 QString::null,
					 this,
					 SLOT( navigateHome() ),
					 this);
	QWhatsThis::add( m_toolbarIconBackward, i18n( "Click this button to move to the home page") );	

	// Initialize history storage
	m_historyMaxSize = 25;
	invalidate();
}


KCHMNavToolbar::~KCHMNavToolbar()
{
}

void KCHMNavToolbar::navigateForward( )
{
	if ( m_historyCurrentPos <  m_history.size() )
	{
		m_historyCurrentPos++;
	
		::mainWindow->openPage( m_history[m_historyCurrentPos].getUrl() );
		::mainWindow->getViewWindow()->setScrollbarPosition( (
				m_history[m_historyCurrentPos].getScrollPosition() ) );
	}
	
	updateIconStatus();
}

void KCHMNavToolbar::navigateBack( )
{
	if ( m_historyCurrentPos > 0 )
	{
		m_historyCurrentPos--;
	
		::mainWindow->openPage( m_history[m_historyCurrentPos].getUrl() );
		::mainWindow->getViewWindow()->setScrollbarPosition( (
				m_history[m_historyCurrentPos].getScrollPosition() ) );
	}
	
	updateIconStatus();
}

void KCHMNavToolbar::navigateHome( )
{
	::mainWindow->openPage( ::mainWindow->getChmFile()->HomePage(), true );
}

void KCHMNavToolbar::invalidate( )
{
	m_historyCurrentPos = 0;
	m_history.clear();
	
	updateIconStatus();
}

void KCHMNavToolbar::addNavigationHistory( const QString & url, int scrollpos )
{
	// shred the 'forward' history
	if ( m_historyCurrentPos < m_history.size() )
		m_history.erase( m_history.at( m_historyCurrentPos ), m_history.end());

	// do not grow the history if already max size
	if ( m_history.size() >= m_historyMaxSize )
		m_history.pop_front();

	m_history.push_back( KCHMUrlHistory( url, scrollpos ) );
	m_historyCurrentPos = m_history.size();
			
	updateIconStatus();
		
	// Dump history
#if 0
	qDebug("History dump (%d entries)", m_history.size() );
	for ( unsigned int i = 0; i < m_history.size(); i++ )
		qDebug("[%02d]: %s [%d]", i, m_history[i].getUrl().ascii(),  m_history[i].getScrollPosition());
#endif
}

void KCHMNavToolbar::updateIconStatus( )
{
	m_toolbarIconBackward->setEnabled( m_historyCurrentPos > 0 );
	m_toolbarIconForward->setEnabled ( m_historyCurrentPos < m_history.size() );
}


#include "kchmnavtoolbar.moc"
