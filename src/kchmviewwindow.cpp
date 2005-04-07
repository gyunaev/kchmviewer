
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

#include "kchmviewwindow.h"
#include "kchmconfig.h"

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

KCHMViewWindow::KCHMViewWindow( QWidget * parent, bool resolve_images )
	: QTextBrowser (parent)
{
	m_sourcefactory = 0;
	m_resolveImages = resolve_images;
	setTextFormat ( Qt::RichText );

	invalidate();
}

KCHMViewWindow::~KCHMViewWindow()
{
	delete m_sourcefactory;
}

bool KCHMViewWindow::LoadPage( QString url )
{
	// If we're using a memory saving scheme, we destroy MimeSourceFactory (including all the stored data)
	// when opening a new page. It saves some memory, but spends more time while looking for already loaded
	// images and HTML pages
#if !defined (KEEP_ALL_OPENED_DATA_IN_SOURCE_FACTORY)
	delete m_sourcefactory;
	m_sourcefactory = new KCHMSourceFactory;
	setMimeSourceFactory (m_sourcefactory);
#endif	

	makeURLabsolute (url);
	setSource (url);
	return true;
}

void KCHMViewWindow::setSource( const QString & url )
{
	if ( !m_shouldSkipSourceChange )
	{
		QTextBrowser::setSource( url );
		m_openedPage = url;
	}
	else
		m_shouldSkipSourceChange = false;
}

void KCHMViewWindow::zoomIn( )
{
	m_zoomfactor++;
	QTextBrowser::zoomIn( );
}

void KCHMViewWindow::zoomOut( )
{
	m_zoomfactor--;
	QTextBrowser::zoomOut( );
}

void KCHMViewWindow::setZoomFactor( int zoom )
{
	m_zoomfactor = zoom;

	if ( zoom < 0 )
		QTextBrowser::zoomOut( -zoom );
	else if ( zoom > 0 )
		QTextBrowser::zoomIn( zoom);
}

void KCHMViewWindow::invalidate( )
{
	delete m_sourcefactory;
	m_sourcefactory = new KCHMSourceFactory (this);
	setMimeSourceFactory (m_sourcefactory);

	m_zoomfactor = 0;
	m_shouldSkipSourceChange = false;
	m_base_url = "/";
	m_openedPage = QString::null;
}


bool KCHMViewWindow::isRemoteURL( const QString & url, QString & protocol )
{
	// Check whether the URL is external
	QRegExp uriregex ( "^(\\w+):\\/\\/" );

	if ( uriregex.search ( url ) != -1 )
	{
		QString proto = uriregex.cap ( 1 ).lower();
		
		// Filter the URLs which need to be opened by a browser
		if ( proto == "http" 
		|| proto == "ftp"
		|| proto == "mailto"
		|| proto == "news" )
		{
			protocol = proto;
			return true;
		}
	}

	return false;
}

bool KCHMViewWindow::isJavascriptURL( const QString & url )
{
	return url.startsWith ("javascript://");
}

// Parse urls like "ms-its:file name.chm::/topic.htm"
bool KCHMViewWindow::isNewChmURL( const QString & url, QString & chmfile, QString & page )
{
	QRegExp uriregex ( "^ms-its:(.*)::(.*)$" );

	if ( uriregex.search ( url ) != -1 )
	{
		chmfile = uriregex.cap ( 1 );
		page = uriregex.cap ( 2 );
		
		return true;
	}

	return false;
}


QString KCHMViewWindow::makeURLabsolute ( const QString & url, bool set_as_base )
{
	QString p1, p2, newurl = url;

	if ( !isRemoteURL (url, p1)
	&& !isJavascriptURL (url)
	&& !isNewChmURL (url, p1, p2) )
	{
		newurl = QDir::cleanDirPath (url);

		// Normalize url, so it becomes absolute
		if ( newurl[0] != '/' )
			newurl = m_base_url + "/" + newurl;
	
		newurl = QDir::cleanDirPath (newurl);

		if ( set_as_base )
		{
			m_base_url = newurl;
		
			// and set up new baseurl
			int i = newurl.findRev('/');
			if ( i != -1 )
				m_base_url = QDir::cleanDirPath (newurl.left (i + 1));
		}
	}

//qDebug ("KCHMViewWindow::makeURLabsolute (%s) -> (%s)", url.ascii(), newurl.ascii());
	return newurl;
}


QString KCHMViewWindow::makeURLabsoluteIfNeeded ( const QString & url )
{
	QString p1, p2, newurl = url;

	if ( !isRemoteURL (url, p1)
	&& !isJavascriptURL (url)
	&& !isNewChmURL (url, p1, p2) )
	{
		newurl = QDir::cleanDirPath (url);

		// Normalize url, so it becomes absolute
		if ( newurl[0] != '/' )
			newurl = "/" + newurl;
	}

//qDebug ("KCHMViewWindow::makeURLabsolute (%s) -> (%s)", url.ascii(), newurl.ascii());
	return newurl;
}
