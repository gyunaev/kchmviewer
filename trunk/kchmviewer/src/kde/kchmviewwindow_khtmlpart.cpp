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

#include <qclipboard.h>

#include <khtmlview.h>
#include <kfinddialog.h>

#include "kde-qt.h"
#include "kchmmainwindow.h"
#include "kchmconfig.h"
#include "kchmviewwindow_khtmlpart.h"


QWidget * KCHMViewWindow_KHTMLPart::getQWidget()
{
	 return view();
}

KCHMViewWindow_KHTMLPart::KCHMViewWindow_KHTMLPart( QTabWidget * parent )
	: KHTMLPart ( parent ), KCHMViewWindow ( parent )
{
	m_zoomfactor = 0;
	m_currentEncoding = 0;

	invalidate();

	connect( browserExtension(), SIGNAL( openUrlRequest( const KUrl&, const KParts::OpenUrlArguments&, const KParts::BrowserArguments& ) ),
			 this, SLOT ( onOpenURLRequest( const KUrl &, const KParts::OpenUrlArguments &, const KParts::BrowserArguments& )) );
	
	connect( this, SIGNAL ( popupMenu ( const QString &, const QPoint &) ),
			this, SLOT ( onPopupMenu ( const QString &, const QPoint &) ) );
}


KCHMViewWindow_KHTMLPart::~KCHMViewWindow_KHTMLPart()
{
}

bool KCHMViewWindow_KHTMLPart::openPage (const QString& url)
{
	// Set or change the encoding
	if ( m_currentEncoding != ::mainWindow->chmFile()->currentEncoding()
	&& appConfig.m_advAutodetectEncoding )
	{
		m_currentEncoding = ::mainWindow->chmFile()->currentEncoding();
		setEncoding ( m_currentEncoding->qtcodec, TRUE );
	}
	
	QString fullurl = "ms-its:" + ::mainWindow->getOpenedFileName() + "::" + url;
	KHTMLPart::openUrl ( KUrl(fullurl) );
	
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

bool KCHMViewWindow_KHTMLPart::printCurrentPage()
{
	view()->print();
	return true;
}

void KCHMViewWindow_KHTMLPart::onOpenURLRequest( const KUrl &url, const KParts::OpenUrlArguments &, const KParts::BrowserArguments&  )
{
	bool notused;
	emit linkClicked ( url.prettyUrl(), notused );
}

void KCHMViewWindow_KHTMLPart::slotLinkClicked( const QString & newlink )
{
	bool notused;
	emit linkClicked (newlink, notused);
}


void KCHMViewWindow_KHTMLPart::clipSelectAll()
{
	selectAll ();
}

void KCHMViewWindow_KHTMLPart::clipCopy()
{
	QString text = selectedText();
	
	if ( !text.isEmpty() )
		QApplication::clipboard()->setText( text );
}

void KCHMViewWindow_KHTMLPart::onPopupMenu ( const QString &url, const QPoint & point )
{
	QMenu * menu = getContextMenu( url, view() );
	menu->exec( point );
}


void KCHMViewWindow_KHTMLPart::find( const QString& text, int flags )
{
	long options = 0;
	
	if ( flags & SEARCH_CASESENSITIVE )
		options |= KFind::CaseSensitive;
 
	if ( flags & SEARCH_WHOLEWORDS )
		options |= KFind::WholeWordsOnly;
		
	findText ( text, options, ::mainWindow, 0 );
}

void KCHMViewWindow_KHTMLPart::onFindNext()
{
	findTextNext( false );
}

void KCHMViewWindow_KHTMLPart::onFindPrevious()
{
	findTextNext( true );
}
