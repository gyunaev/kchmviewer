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

// Do not use tr() or i18n() in this file - this class is not derived from QObject.

#include <qregexp.h>
#include <qstring.h>
#include <qdir.h>

#include "libchmfile.h"
#include "libchmurlfactory.h"

#include "kchmconfig.h"
#include "kchmviewwindow.h"
#include "kchmmainwindow.h"
#include "kchmviewwindowmgr.h"


KCHMViewWindow::KCHMViewWindow( QTabWidget * parent )
{
	invalidate();
	m_contextMenu = 0;
	m_contextMenuLink = 0;
	m_historyMaxSize = 25;
	
	m_parentTabWidget = parent;
}

KCHMViewWindow::~KCHMViewWindow()
{
}

void KCHMViewWindow::invalidate( )
{
	m_base_url = "/";
	m_openedPage = QString::null;
	m_newTabLinkKeeper = QString::null;

	m_historyCurrentPos = 0;
	m_history.clear();
	
	updateNavigationToolbar();
}



QString KCHMViewWindow::makeURLabsolute ( const QString & url, bool set_as_base )
{
	QString p1, p2, newurl = url;

	if ( !LCHMUrlFactory::isRemoteURL (url, p1)
	&& !LCHMUrlFactory::isJavascriptURL (url)
	&& !LCHMUrlFactory::isNewChmURL (url, p1, p2) )
	{
		newurl = QDir::cleanPath (url);

		// Normalize url, so it becomes absolute
		if ( newurl[0] != '/' )
			newurl = m_base_url + "/" + newurl;
	
		newurl = QDir::cleanPath (newurl);

		if ( set_as_base )
		{
			m_base_url = newurl;
		
			// and set up new baseurl
			int i = newurl.lastIndexOf('/');
			if ( i != -1 )
				m_base_url = QDir::cleanPath (newurl.left (i + 1));
		}
	}

	//qDebug ("KCHMViewWindow::makeURLabsolute (%s) -> (%s)", url.ascii(), newurl.ascii());
	return newurl;
}

bool KCHMViewWindow::openUrl ( const QString& origurl )
{
	QString chmfile, page, newurl = origurl;

	if ( origurl.isEmpty() )
		return true;

	// URL could be a complete ms-its link. The file should be already loaded (for QTextBrowser),
	// or will be loaded (for kio slave). We care only about the path component.
	if ( LCHMUrlFactory::isNewChmURL( newurl, chmfile, page ) )
	{
		// If a new chm file is opened here, and we do not use KCHMLPart, we better abort
		if ( chmfile != ::mainWindow->getOpenedFileBaseName() && appConfig.m_usedBrowser != KCHMConfig::BROWSER_KHTMLPART )
			qFatal("KCHMViewWindow::openUrl(): opened new chm file %s while current is %s",
				   qPrintable( chmfile ),
				   qPrintable( ::mainWindow->getOpenedFileName() ) );

		// It is OK to have a new file in chm for KHTMLPart
		newurl = page;
	}

	makeURLabsolute (newurl);
	handleStartPageAsImage( newurl );
	
	if ( openPage (newurl) )
	{
		m_newTabLinkKeeper = QString::null;
		m_openedPage = newurl;
		
		// If m_openedPage contains #, strip it, and everything after it
		int hash = m_openedPage.indexOf( '#' );
		if ( hash != -1 )
			m_openedPage = m_openedPage.left( hash );
			
		mainWindow->viewWindowMgr()->setTabName( this );
		return true;
	}

	return false;
}

void KCHMViewWindow::handleStartPageAsImage( QString & link )
{
	// Handle pics
	if ( link.endsWith( ".jpg", Qt::CaseInsensitive )
	|| link.endsWith( ".jpeg", Qt::CaseInsensitive )
	|| link.endsWith( ".gif", Qt::CaseInsensitive )
	|| link.endsWith( ".png", Qt::CaseInsensitive )
	|| link.endsWith( ".bmp", Qt::CaseInsensitive ) )
		link += LCHMUrlFactory::getInternalUriExtension();
}


QMenu * KCHMViewWindow::createStandardContextMenu( QWidget * parent )
{
	QMenu * contextMenu = new QMenu( parent );
	
	contextMenu->addAction( "&Copy", ::mainWindow, SLOT(slotBrowserCopy()) );
	contextMenu->addAction( "&Select all", ::mainWindow, SLOT(slotBrowserSelectAll()) );
		
	return contextMenu;
}


QMenu * KCHMViewWindow::getContextMenu( const QString & link, QWidget * parent )
{
	if ( link.isEmpty() )
	{
		// standard context menu
		if ( !m_contextMenu )
			m_contextMenu = createStandardContextMenu( parent );
		
		return m_contextMenu;
	}
	else
	{
		// Open in New Tab context menu
		// standard context menu
		if ( !m_contextMenuLink )
		{
			m_contextMenuLink = createStandardContextMenu( parent );
			m_contextMenuLink->addSeparator();
			
			m_contextMenuLink->addAction( "&Open this link in a new tab", ::mainWindow, SLOT(onOpenPageInNewTab()), QKeySequence("Shift+Enter") );
			
			m_contextMenuLink->addAction( "&Open this link in a new background tab", ::mainWindow, SLOT(onOpenPageInNewBackgroundTab()), QKeySequence("Ctrl+Enter") );
		}
		
		setTabKeeper( link );
		return m_contextMenuLink;
	}
}

QString KCHMViewWindow::getTitle() const
{
	QString title = ::mainWindow->chmFile()->getTopicByUrl( m_openedPage );
	
	if ( title.isEmpty() )
		title = m_openedPage;
	
	return title;
}


void KCHMViewWindow::navigateForward()
{
	if ( m_historyCurrentPos < m_history.size() )
	{
		m_historyCurrentPos++;		
		::mainWindow->openPage( m_history[m_historyCurrentPos].getUrl() );
		setScrollbarPosition( m_history[m_historyCurrentPos].getScrollPosition() );
		
		// By default navigation starts with empty array, and a new entry is added when
		// you change the current page (or it may not be added). So to have the whole system
		// worked, the m_historyCurrentPos should never be m_history.size() - 1, it should be
		// either greater or lesser.
		// 
		// This is a dirty hack - but the whole navigation system now looks to me like
		// it was written by some drunk monkey - which is probably not far from The Real Truth.
		// Shame on me - Tim.
		if ( m_historyCurrentPos == (m_history.size() - 1) )
			m_historyCurrentPos++;
	}
	
	updateNavigationToolbar();
}

void KCHMViewWindow::navigateBack( )
{
	if ( m_historyCurrentPos > 0 )
	{
		// If we're on top of list, and pressing Back, the last page is still
		// not in list - so add it, if it is not still here
		if ( m_historyCurrentPos == m_history.size() )
		{
			if ( m_history[m_historyCurrentPos-1].getUrl() != m_openedPage )
				m_history.push_back( KCHMUrlHistory( m_openedPage, getScrollbarPosition() ) );
			else
			{
				// part 2 of the navigation hack - see navigateForward() comment
				m_history[m_historyCurrentPos-1].setScrollPosition( getScrollbarPosition() );
				m_historyCurrentPos--;
			}
		}

		m_historyCurrentPos--;
	
		::mainWindow->openPage( m_history[m_historyCurrentPos].getUrl() );
		setScrollbarPosition( m_history[m_historyCurrentPos].getScrollPosition() );
	}
	
	updateNavigationToolbar();
}

void KCHMViewWindow::navigateHome( )
{
	::mainWindow->openPage( ::mainWindow->chmFile()->homeUrl() );
}

void KCHMViewWindow::addNavigationHistory( const QString & url, int scrollpos )
{
	// shred the 'forward' history
	if ( m_historyCurrentPos < m_history.size() )
		m_history.erase( m_history.begin() + m_historyCurrentPos, m_history.end() );

	// do not grow the history if already max size
	if ( m_history.size() >= m_historyMaxSize )
		m_history.pop_front();

	m_history.push_back( KCHMUrlHistory( url, scrollpos ) );
	m_historyCurrentPos = m_history.size();
			
	updateNavigationToolbar();
}

void KCHMViewWindow::updateNavigationToolbar( )
{
	// Dump navigation for debugging
#if 0
	qDebug("\nNavigation dump (%d entries, current pos %d)", m_history.size(), m_historyCurrentPos );
	for ( unsigned int i = 0; i < m_history.size(); i++ )
		qDebug("[%02d]: %s [%d]", i, m_history[i].getUrl().ascii(),  m_history[i].getScrollPosition());
#endif
	
	if ( mainWindow )
	{
		mainWindow->navSetBackEnabled( m_historyCurrentPos > 0 );
		mainWindow->navSetForwardEnabled( m_historyCurrentPos < (m_history.size() - 1) );
	}
}


void KCHMViewWindow::setTabKeeper( const QString & link )
{
	// If we clicked on relative link, make sure we convert it to absolute right now,
	// because later we will not have access to this view window variables
	m_newTabLinkKeeper = link;
	if ( m_newTabLinkKeeper[0] == '#' && !m_openedPage.isEmpty() )
	{
			// Clean up opened page URL
		int pos = m_openedPage.indexOf('#');
		QString fixedpath = pos == -1 ? m_openedPage : m_openedPage.left (pos);
		m_newTabLinkKeeper = fixedpath + m_newTabLinkKeeper;
	}
		
	m_newTabLinkKeeper = makeURLabsolute( m_newTabLinkKeeper, false );
}
