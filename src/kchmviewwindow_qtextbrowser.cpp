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

#include <qregexp.h>
#include <qstring.h>
#include <qdir.h>

#include "kchmviewwindow_qtextbrowser.h"

/*
 * If defined, all the data viewed is kept in source factory. It increases the response time
 * when a user opens the page he has already seen, in cost of everything which has been opened 
 * is stored in memory, increasing memory usage.
 *
 * If not defined, on any page change the source factory cleans up, saving the memory, but 
 * increasing the page loading time in case the page has the same images, or the page is opened
 * second time.
 */
#define KEEP_ALL_OPENED_DATA_IN_SOURCE_FACTORY

KCHMViewWindow_QTextBrowser::KCHMViewWindow_QTextBrowser( QWidget * parent )
	: QTextBrowser ( parent ), KCHMViewWindow ( parent )
{
	m_zoomfactor = 0;
	m_sourcefactory = 0;
	invalidate();
	
	setTextFormat ( Qt::RichText );
	connect( this, SIGNAL( linkClicked (const QString &) ), this, SLOT( slotLinkClicked(const QString &) ) );
}


KCHMViewWindow_QTextBrowser::~KCHMViewWindow_QTextBrowser()
{
	delete m_sourcefactory;
}

bool KCHMViewWindow_QTextBrowser::openPage (const QString& url)
{
	// If we're using a memory saving scheme, we destroy MimeSourceFactory (including all the stored data)
	// when opening a new page. It saves some memory, but spends more time while looking for already loaded
	// images and HTML pages
#if !defined (KEEP_ALL_OPENED_DATA_IN_SOURCE_FACTORY)
	delete m_sourcefactory;
	m_sourcefactory = new KCHMSourceFactory;
	setMimeSourceFactory (m_sourcefactory);
#endif	

	setSource (url);
	return true;
}

void KCHMViewWindow_QTextBrowser::setSource ( const QString & name )
{
	if ( m_allowSourceChange )
	{
		clear();
		QTextBrowser::setSource (name);
	}
	else
		m_allowSourceChange = true;
}

void KCHMViewWindow_QTextBrowser::setZoomFactor( int zoom )
{
	m_zoomfactor = zoom;
	
	if ( zoom < 0 )
		QTextBrowser::zoomOut( -zoom );
	else if ( zoom > 0 )
		QTextBrowser::zoomIn( zoom);
}

void KCHMViewWindow_QTextBrowser::invalidate( )
{
	delete m_sourcefactory;
	m_sourcefactory = new KCHMSourceFactory (this);
	setMimeSourceFactory (m_sourcefactory);
	m_zoomfactor = 0;
	m_allowSourceChange = true;
	
	KCHMViewWindow::invalidate( );
}

int KCHMViewWindow_QTextBrowser::getScrollbarPosition( )
{
	return contentsY ();
}

void KCHMViewWindow_QTextBrowser::setScrollbarPosition( int pos )
{
	setContentsPos (0, pos);
}

void KCHMViewWindow_QTextBrowser::addZoomFactor( int value )
{
	setZoomFactor( m_zoomfactor + value);
}

void KCHMViewWindow_QTextBrowser::slotLinkClicked( const QString & newlink )
{
	emit signalLinkClicked (newlink, m_allowSourceChange);
}

void KCHMViewWindow_QTextBrowser::emitSignalHistoryAvailabilityChanged( bool enable_backward, bool enable_forward )
{
	emit signalHistoryAvailabilityChanged( enable_backward, enable_forward );
}
