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

#include <qprinter.h>
#include <qpainter.h>
#include <qsimplerichtext.h>
#include <qpaintdevicemetrics.h>

#include "kde-qt.h"
#include "kchmmainwindow.h"
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

KCHMViewWindow_QTextBrowser::KCHMViewWindow_QTextBrowser( QTabWidget * parent )
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
		// Do URI decoding, qtextbrowser does stupid job.
		QString fixedname = decodeUrl( name );
		QTextBrowser::setSource (fixedname);
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
	m_searchLastIndex = 0;
	m_searchLastParagraph = 0;
	m_searchText = QString::null;
	reload();
	
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
	setZoomFactor( value);
}

void KCHMViewWindow_QTextBrowser::slotLinkClicked( const QString & newlink )
{
	emit signalLinkClicked (newlink, m_allowSourceChange);
}


bool KCHMViewWindow_QTextBrowser::printCurrentPage( )
{
#if !defined (QT_NO_PRINTER)
    QPrinter printer( QPrinter::HighResolution );
    printer.setFullPage(TRUE);
	
	if ( printer.setup( this ) )
	{
		QPainter p( &printer );
		
		if( !p.isActive() ) // starting printing failed
			return false;
		
		QPaintDeviceMetrics metrics(p.device());
		int dpiy = metrics.logicalDpiY();
		int margin = (int) ( (2/2.54)*dpiy ); // 2 cm margins
		QRect body( margin, margin, metrics.width() - 2*margin, metrics.height() - 2*margin );
		QSimpleRichText richText( text(),
								  QFont(),
								  context(),
								  styleSheet(),
								  mimeSourceFactory(),
								  body.height() );
		richText.setWidth( &p, body.width() );
		QRect view( body );
		
		int page = 1;
		
		do
		{
			richText.draw( &p, body.left(), body.top(), view, colorGroup() );
			view.moveBy( 0, body.height() );
			p.translate( 0 , -body.height() );
			p.drawText( view.right() - p.fontMetrics().width( QString::number(page) ),
						view.bottom() + p.fontMetrics().ascent() + 5, QString::number(page) );
			
			if ( view.top()  >= richText.height() )
				break;
			
			QString msg = i18n( "Printing (page %1)...") .arg(page);
			::mainWindow->showInStatusBar( msg );
			
			printer.newPage();
			page++;
		}
		while (TRUE);
	
		::mainWindow->showInStatusBar( i18n( "Printing completed") );
		return true;
	}

	::mainWindow->showInStatusBar( i18n( "Printing aborted") );
	return false;

#else /* QT_NO_PRINTER */

	QMessageBox::warning( this, 
		i18n( "%1 - could not print") . arg(APP_NAME),
		i18n( "Could not print.\nYour Qt library has been compiled without printing support");
	return false;

#endif /* QT_NO_PRINTER */
}


void KCHMViewWindow_QTextBrowser::searchWord( const QString & word, bool forward, bool )
{
	if ( m_searchText == word )
	{
		if ( forward && (m_searchLastIndex || m_searchLastParagraph) )
			m_searchLastIndex += m_searchText.length();
	}
	else
	{
		m_searchLastParagraph = m_searchLastIndex = 0;
		m_searchText = word;
	}

	if ( find (m_searchText, false, false, forward, &m_searchLastParagraph, &m_searchLastIndex) )
		::mainWindow->showInStatusBar( i18n( "Search failed") );
}

void KCHMViewWindow_QTextBrowser::clipSelectAll( )
{
	selectAll (TRUE);
}

void KCHMViewWindow_QTextBrowser::clipCopy( )
{
	copy ();
}


// Shamelessly stolen from Qt
QString KCHMViewWindow_QTextBrowser::decodeUrl( const QString &input )
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
			a = input[++i];
			b = input[++i];

			if (a >= '0' && a <= '9') a -= '0';
			else if (a >= 'a' && a <= 'f') a = a - 'a' + 10;
			else if (a >= 'A' && a <= 'F') a = a - 'A' + 10;

			if (b >= '0' && b <= '9') b -= '0';
			else if (b >= 'a' && b <= 'f') b  = b - 'a' + 10;
			else if (b >= 'A' && b <= 'F') b  = b - 'A' + 10;

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

QPopupMenu * KCHMViewWindow_QTextBrowser::createPopupMenu( const QPoint & pos )
{
	KQPopupMenu * menu = getContextMenu( anchorAt( pos ), this );
	menu->exec( mapToGlobal( contentsToViewport( pos ) ) );
	return 0;
}

#include "kchmviewwindow_qtextbrowser.moc"
