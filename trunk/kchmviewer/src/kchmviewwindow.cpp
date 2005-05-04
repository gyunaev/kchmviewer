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


KCHMViewWindow::KCHMViewWindow( QWidget * parent )
{
	m_historyMaxSize = 25;
	invalidate();
}

KCHMViewWindow::~KCHMViewWindow()
{
}

void KCHMViewWindow::invalidate( )
{
	m_base_url = "/";
	m_openedPage = QString::null;
	m_historyCurrentSize = 0;
	m_historyTopOffset = 0;
	m_history.clear();
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

bool KCHMViewWindow::openUrl ( const QString& url, bool addHistory )
{
	if ( !url )
		return true;

	makeURLabsolute (url);
	
	if ( openPage (url) )
	{
		if ( addHistory && url && m_openedPage != url )
		{
			// do not grow the history if already max size
			if ( m_historyCurrentSize >= m_historyMaxSize )
				m_history.pop_front();
			else
				m_historyCurrentSize++;

			// shred the 'forward' history
			if ( m_historyTopOffset != 0 )
			{
				m_history.erase (++m_historyIterator, m_history.end());
				m_historyCurrentSize -= m_historyTopOffset;
				m_historyTopOffset = 0;
			}

			m_history.push_back (url);
			m_historyIterator = m_history.fromLast();
		}

		m_openedPage = url;
		checkHistoryAvailability( );
		return true;
	}
	
	return false;
}

void KCHMViewWindow::checkHistoryAvailability( )
{
	bool enable_backward = m_historyCurrentSize && m_historyIterator != m_history.begin();
	bool enable_forward = m_historyTopOffset != 0;

	emitSignalHistoryAvailabilityChanged (enable_backward, enable_forward);
}

void KCHMViewWindow::navigateBack( )
{
	m_historyIterator--;
	m_historyTopOffset++;
	
	openUrl ( *m_historyIterator, false );
	checkHistoryAvailability();
}

void KCHMViewWindow::navigateForward( )
{
	m_historyIterator++;
	m_historyTopOffset--;
	
	openUrl ( *m_historyIterator, false );
	checkHistoryAvailability();
}
