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
#include "kchmmainwindow.h"
#include "xchmfile.h"
#include "kchmconfig.h"
#include "kchmviewwindow_khtmlpart.h"

#if defined (USE_KDE)

#include <khtmlview.h>
#include <kfinddialog.h>

KCHMViewWindow_KHTMLPart::KCHMViewWindow_KHTMLPart( QWidget * parent )
	: KHTMLPart ( parent ), KCHMViewWindow ( parent )
{
	m_zoomfactor = 0;
	m_currentEncoding = 0;
	m_searchForward = true;

	invalidate();

	m_contextMenu = 0;

	connect( browserExtension(), SIGNAL( openURLRequest( const KURL &, const KParts::URLArgs & ) ),
		this, SLOT ( onOpenURLRequest( const KURL &, const KParts::URLArgs & )) );
	
	connect( this, SIGNAL ( popupMenu ( const QString &, const QPoint &) ),
		this, SLOT ( onPopupMenu ( const QString &, const QPoint &) ) );
}


KCHMViewWindow_KHTMLPart::~KCHMViewWindow_KHTMLPart()
{
}

bool KCHMViewWindow_KHTMLPart::openPage (const QString& url)
{
	// Set or change the encoding
	if ( m_currentEncoding != ::mainWindow->getChmFile()->getCurrentEncoding() )
	{
		m_currentEncoding = ::mainWindow->getChmFile()->getCurrentEncoding();
		setEncoding ( m_currentEncoding->qtcodec, TRUE );
	}
	
	QString fullurl = "ms-its:" + ::mainWindow->getOpenedFileName() + "::" + url;
	openURL ( KURL(fullurl) );
	return true;
}

void KCHMViewWindow_KHTMLPart::setZoomFactor( int zoom )
{
	m_zoomfactor = zoom;
	
	// Default ZoomFactor is 100, any increase or decrease should modify this value.
	KHTMLPart::setZoomFactor ( 100 + (m_zoomfactor * 10) );
}

void KCHMViewWindow_KHTMLPart::invalidate( )
{
	m_zoomfactor = 0;
	m_searchForward = true;
	m_searchText = QString::null;

	setJScriptEnabled ( appConfig.m_kdeEnableJS );
	setJavaEnabled ( appConfig.m_kdeEnableJava );
	setMetaRefreshEnabled ( appConfig.m_kdeEnableRefresh );
	setPluginsEnabled ( appConfig.m_kdeEnablePlugins );
	
	KCHMViewWindow::invalidate( );
}

int KCHMViewWindow_KHTMLPart::getScrollbarPosition( )
{
	return view()->contentsY ();
}

void KCHMViewWindow_KHTMLPart::setScrollbarPosition( int pos )
{
	view()->scrollBy (0, pos);
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
	if ( word != m_searchText || forward != m_searchForward )
	{
		m_searchText = word;
		m_searchForward = forward;
		
		findText ( word, forward ? 0 : KFindDialog::FindBackwards, ::mainWindow, 0 );
	}
	
	findTextNext ();
}

void KCHMViewWindow_KHTMLPart::onOpenURLRequest( const KURL & url, const KParts::URLArgs & )
{
	bool sourcechange = true;
	emit signalLinkClicked ( url.prettyURL(), sourcechange );
}


void KCHMViewWindow_KHTMLPart::clipSelectAll()
{
	selectAll ();
}

void KCHMViewWindow_KHTMLPart::clipCopy()
{
	kapp->copy();
}

void  KCHMViewWindow_KHTMLPart::onPopupMenu ( const QString &, const QPoint & point )
{
	// we create the menu object here, because ::mainWindow is not defined in 
	// KCHMViewWindow_KHTMLPart constructor
	if ( !m_contextMenu )
	{
		m_contextMenu = new KPopupMenu( view() );
		m_contextMenu->insertTitle ( i18n( "menu item", "Editor" ) );
		m_contextMenu->insertItem ( i18n( "menu item", "&Copy"), ::mainWindow, SLOT(slotBrowserCopy()) );
		m_contextMenu->insertItem ( i18n( "menu item", "&Select all"), ::mainWindow, SLOT(slotBrowserSelectAll()) );
	}
	
	m_contextMenu->exec( point );
}

#include "kchmviewwindow_khtmlpart.moc"

#endif /* USE_KDE */

//TODO: KDE: about box and "About KDE"
