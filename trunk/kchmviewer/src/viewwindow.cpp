/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

// Do not use tr() or i18n() in this file - this class is not derived from QObject.

#include <QRegExp>
#include <QString>
#include <QPrinter>
#include <QPrintDialog>

#include <QWebView>
#include <QWebFrame>

#include "libchmurlfactory.h"

#include "config.h"
#include "viewwindow.h"
#include "mainwindow.h"
#include "viewwindowmgr.h"
#include "qwebviewnetwork.h"

static const qreal ZOOM_FACTOR_CHANGE = 0.1;


ViewWindow::ViewWindow( QWidget * parent )
	: QWebView ( parent )
{
	invalidate();
	m_contextMenu = 0;
	m_contextMenuLink = 0;
	m_historyMaxSize = 25;

	// Use our network emulation layer
	page()->setNetworkAccessManager( new KCHMNetworkAccessManager(this) );

	// All links are going through us
	page()->setLinkDelegationPolicy( QWebPage::DelegateAllLinks );

	connect( this, SIGNAL( loadFinished(bool)), this, SLOT( onLoadFinished(bool)) );
}

ViewWindow::~ViewWindow()
{
}

void ViewWindow::invalidate( )
{
	m_base_url = "/";
	m_openedPage = QString::null;
	m_newTabLinkKeeper = QString::null;

	m_storedScrollbarPosition = 0;
	m_historyCurrentPos = 0;
	m_history.clear();
	
	reload();
	updateNavigationToolbar();
}


QString ViewWindow::makeURLabsolute ( const QString & url, bool set_as_base )
{
	QString p1, p2, newurl = url;

	if ( !LCHMUrlFactory::isRemoteURL (url, p1)
	&& !LCHMUrlFactory::isJavascriptURL (url)
	&& !LCHMUrlFactory::isNewChmURL (url, mainWindow->getOpenedFileName(), p1, p2) )
	{
		newurl = QDir::cleanPath (url);

		// Normalize url, so it becomes absolute
		if ( newurl[0] != '/' )
		{
			if ( m_base_url != "/" )
				newurl = m_base_url + "/" + newurl;
			else
				newurl = "/" + newurl;
		}
	
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

	//qDebug ("ViewWindow::makeURLabsolute (%s) -> (%s)", url.ascii(), newurl.ascii());
	return newurl;
}

bool ViewWindow::openUrl ( const QString& origurl )
{
	QString chmfile, page, newurl = origurl;

	if ( origurl.isEmpty() )
		return true;

	// URL could be a complete ms-its link. The file should be already loaded (for QTextBrowser),
	// or will be loaded (for kio slave). We care only about the path component.
	if ( LCHMUrlFactory::isNewChmURL( newurl, mainWindow->getOpenedFileName(), chmfile, page ) )
	{
		// If a new chm file is opened here, we better abort
		if ( chmfile != ::mainWindow->getOpenedFileBaseName()  )
			qFatal("ViewWindow::openUrl(): opened new chm file %s while current is %s",
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

void ViewWindow::handleStartPageAsImage( QString & link )
{
	// Handle pics
	if ( link.endsWith( ".jpg", Qt::CaseInsensitive )
	|| link.endsWith( ".jpeg", Qt::CaseInsensitive )
	|| link.endsWith( ".gif", Qt::CaseInsensitive )
	|| link.endsWith( ".png", Qt::CaseInsensitive )
	|| link.endsWith( ".bmp", Qt::CaseInsensitive ) )
		link += LCHMUrlFactory::getInternalUriExtension();
}


QMenu * ViewWindow::createStandardContextMenu( QWidget * parent )
{
	QMenu * contextMenu = new QMenu( parent );
	
	contextMenu->addAction( "&Copy", ::mainWindow, SLOT(slotBrowserCopy()) );
	contextMenu->addAction( "&Select all", ::mainWindow, SLOT(slotBrowserSelectAll()) );
		
	return contextMenu;
}


QMenu * ViewWindow::getContextMenu( const QString & link, QWidget * parent )
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

QString ViewWindow::getTitle() const
{
	QString title = ::mainWindow->chmFile()->getTopicByUrl( m_openedPage );
	
	if ( title.isEmpty() )
		title = m_openedPage;
	
	return title;
}


void ViewWindow::navigateForward()
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

void ViewWindow::navigateBack( )
{
	if ( m_historyCurrentPos > 0 )
	{
		// If we're on top of list, and pressing Back, the last page is still
		// not in list - so add it, if it is not still here
		if ( m_historyCurrentPos == m_history.size() )
		{
			if ( m_history[m_historyCurrentPos-1].getUrl() != m_openedPage )
				m_history.push_back( UrlHistory( m_openedPage, getScrollbarPosition() ) );
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

void ViewWindow::navigateHome( )
{
	::mainWindow->openPage( ::mainWindow->chmFile()->homeUrl() );
}

void ViewWindow::addNavigationHistory( const QString & url, int scrollpos )
{
	// shred the 'forward' history
	if ( m_historyCurrentPos < m_history.size() )
		m_history.erase( m_history.begin() + m_historyCurrentPos, m_history.end() );

	// do not grow the history if already max size
	if ( m_history.size() >= m_historyMaxSize )
		m_history.pop_front();

	m_history.push_back( UrlHistory( url, scrollpos ) );
	m_historyCurrentPos = m_history.size();
			
	updateNavigationToolbar();
}

void ViewWindow::updateNavigationToolbar( )
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


void ViewWindow::setTabKeeper( const QString & link )
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

bool ViewWindow::openPage(const QString &url)
{
	// Do URI decoding, qtextbrowser does stupid job.
	QString fixedname = decodeUrl( url );

	if ( !fixedname.startsWith( "ms-its:", Qt::CaseInsensitive ) )
		fixedname = "ms-its:" + fixedname;

	load( fixedname );
	return true;
}

bool ViewWindow::printCurrentPage()
{
	QPrinter printer( QPrinter::HighResolution );
	QPrintDialog dlg( &printer, this );

	if ( dlg.exec() != QDialog::Accepted )
	{
		::mainWindow->showInStatusBar( i18n( "Printing aborted") );
		return false;
	}

	print( &printer );
	::mainWindow->showInStatusBar( i18n( "Printing finished") );

	return true;
}

void ViewWindow::setZoomFactor(qreal zoom)
{
	QWebView::setZoomFactor( zoom );
}

qreal ViewWindow::getZoomFactor() const
{
	return zoomFactor();
}

void ViewWindow::zoomIncrease()
{
	setZoomFactor( zoomFactor() + ZOOM_FACTOR_CHANGE );
}

void ViewWindow::zoomDecrease()
{
	setZoomFactor( zoomFactor() - ZOOM_FACTOR_CHANGE );
}

int ViewWindow::getScrollbarPosition()
{
	return page()->currentFrame()->scrollBarValue( Qt::Vertical );
}

void ViewWindow::setScrollbarPosition(int pos)
{
	m_storedScrollbarPosition = pos;
}

void ViewWindow::clipSelectAll()
{
	triggerPageAction( QWebPage::SelectAll );
}

void ViewWindow::clipCopy()
{
	triggerPageAction( QWebPage::Copy );
}

// Shamelessly stolen from Qt
QString ViewWindow::decodeUrl( const QString &input )
{
	QString temp;

	int i = 0;
	int len = input.length();
	int a, b;
	QChar c;
	while (i < len)
	{
		c = input[i];
		if (c == '%' && i + 2 < len)
		{
			a = input[++i].unicode();
			b = input[++i].unicode();

			if (a >= '0' && a <= '9')
				a -= '0';
			else if (a >= 'a' && a <= 'f')
				a = a - 'a' + 10;
			else if (a >= 'A' && a <= 'F')
				a = a - 'A' + 10;

			if (b >= '0' && b <= '9')
				b -= '0';
			else if (b >= 'a' && b <= 'f')
				b  = b - 'a' + 10;
			else if (b >= 'A' && b <= 'F')
				b  = b - 'A' + 10;

			temp.append( (QChar)((a << 4) | b ) );
		}
		else
		{
			temp.append( c );
		}

		++i;
	}

	return temp;
}


QString ViewWindow::anchorAt(const QPoint & pos)
{
	QWebHitTestResult res = page()->currentFrame()->hitTestContent( pos );

	if ( !res.linkUrl().isValid() )
		return QString::null;

	return  res.linkUrl().path();
}


void ViewWindow::mouseReleaseEvent ( QMouseEvent * event )
{
	if ( event->button() == Qt::MidButton )
	{
		QString link = anchorAt( event->pos() );

		if ( !link.isEmpty() )
		{
			setTabKeeper( link );
			::mainWindow->onOpenPageInNewBackgroundTab();
			return;
		}
	}

	QWebView::mouseReleaseEvent( event );
}

bool ViewWindow::findTextInPage(const QString &text, int flags)
{
	QWebPage::FindFlags webkitflags = QWebPage::FindWrapsAroundDocument;

	if ( flags & ViewWindow::SEARCH_BACKWARD )
		webkitflags |= QWebPage::FindBackward;

	if ( flags & ViewWindow::SEARCH_CASESENSITIVE )
		webkitflags |= QWebPage::FindCaseSensitively;

	return findText( text, webkitflags );
}

void ViewWindow::contextMenuEvent(QContextMenuEvent *e)
{
	// From Qt Assistant
	QMenu *m = new QMenu(0);
	QString link = anchorAt( e->pos() );

	if ( !link.isEmpty() )
	{
		m->addAction( i18n("Open Link in a new tab\tShift+LMB"), ::mainWindow, SLOT( onOpenPageInNewTab() ) );
		m->addAction( i18n("Open Link in a new background tab\tCtrl+LMB"), ::mainWindow, SLOT( onOpenPageInNewBackgroundTab() ) );
		m->addSeparator();
		setTabKeeper( link );
	}

	::mainWindow->setupPopupMenu( m );
	m->exec( e->globalPos() );
	delete m;
}

void ViewWindow::onLoadFinished ( bool )
{
	page()->currentFrame()->setScrollBarValue( Qt::Vertical, m_storedScrollbarPosition );
}
