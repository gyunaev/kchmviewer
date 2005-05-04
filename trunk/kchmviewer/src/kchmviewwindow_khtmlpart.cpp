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

#include "kde-qt.h"
#include "kchmmainwindow.h"
#include "kchmviewwindow_khtmlpart.h"

#if defined (USE_KDE)

#include <khtmlview.h>
#include <kfinddialog.h>

KCHMViewWindow_KHTMLPart::KCHMViewWindow_KHTMLPart( QWidget * parent )
	: KHTMLPart ( parent ), KCHMViewWindow ( parent )
{
	m_zoomfactor = 0;
	invalidate();

	setJScriptEnabled(false);
 	setJavaEnabled(false);
 	setMetaRefreshEnabled(false);
 	setPluginsEnabled(false);
	
//	connect( this, SIGNAL( linkClicked (const QString &) ), this, SLOT( slotLinkClicked(const QString &) ) );
}


KCHMViewWindow_KHTMLPart::~KCHMViewWindow_KHTMLPart()
{
}

bool KCHMViewWindow_KHTMLPart::openPage (const QString& url)
{
	QString fullurl = "ms-its:" + ::mainWindow->getOpenedFileName() + "::" + url;
	openURL ( KURL(fullurl) );
	return true;
}

void KCHMViewWindow_KHTMLPart::setZoomFactor( int zoom )
{
	m_zoomfactor = zoom;
/*	
	if ( zoom < 0 )
		QTextBrowser::zoomOut( -zoom );
	else if ( zoom > 0 )
		QTextBrowser::zoomIn( zoom);
*/
}

void KCHMViewWindow_KHTMLPart::invalidate( )
{
	m_zoomfactor = 0;
//	KCHMViewWindow::invalidate( );
}

int KCHMViewWindow_KHTMLPart::getScrollbarPosition( )
{
	return 0; /* contentsY (); */
}

void KCHMViewWindow_KHTMLPart::setScrollbarPosition( int pos )
{
//	setContentsPos (0, pos);
}

void KCHMViewWindow_KHTMLPart::addZoomFactor( int value )
{
	setZoomFactor( m_zoomfactor + value);
}

void KCHMViewWindow_KHTMLPart::slotLinkClicked( const QString & newlink )
{
	bool notused;
	emit signalLinkClicked (newlink, notused);
}

void KCHMViewWindow_KHTMLPart::emitSignalHistoryAvailabilityChanged( bool enable_backward, bool enable_forward )
{
	emit signalHistoryAvailabilityChanged( enable_backward, enable_forward );
}

bool KCHMViewWindow_KHTMLPart::printCurrentPage()
{
	view()->print();
	return true;
}

void KCHMViewWindow_KHTMLPart::searchWord( const QString & word, bool forward, bool )
{
	findText ( word, forward ? 0 : KFindDialog::FindBackwards, ::mainWindow, 0 );
}


#include "kchmviewwindow_khtmlpart.moc"

#endif /* USE_KDE */
