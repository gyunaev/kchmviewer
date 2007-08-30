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


#include <QScrollBar>

#include "kde-qt.h"
#include "libchmurlfactory.h"
#include "kchmmainwindow.h"
#include "kchmviewwindowmgr.h"
#include "kchmviewwindow_qtextbrowser.h"


KCHMViewWindow_QTextBrowser::KCHMViewWindow_QTextBrowser( QTabWidget * parent )
	: QTextBrowser ( parent ), KCHMViewWindow ( parent )
{
	m_zoomfactor = 0;
	invalidate();
	
	setTextFormat ( Qt::RichText );
	connect( this, SIGNAL( anchorClicked ( const QUrl& ) ), this, SLOT( onAnchorClicked ( const QUrl& ) ) );
}


KCHMViewWindow_QTextBrowser::~KCHMViewWindow_QTextBrowser()
{
}

bool KCHMViewWindow_QTextBrowser::openPage (const QString& url)
{
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
	m_zoomfactor = 0;
	m_allowSourceChange = true;
	reload();
	
	KCHMViewWindow::invalidate( );
}

int KCHMViewWindow_QTextBrowser::getScrollbarPosition( )
{
	return verticalScrollBar()->sliderPosition();
}

void KCHMViewWindow_QTextBrowser::setScrollbarPosition( int pos )
{
	verticalScrollBar()->setSliderPosition( pos);
}

void KCHMViewWindow_QTextBrowser::addZoomFactor( int value )
{
	setZoomFactor( value);
}

void KCHMViewWindow_QTextBrowser::onAnchorClicked(const QUrl & url)
{
	emit linkClicked( url.toString(), m_allowSourceChange );
}


bool KCHMViewWindow_QTextBrowser::printCurrentPage( )
{
/* FIXME: printing
#if !defined (QT_NO_PRINTER)
    QPrinter printer( QPrinter::HighResolution );
    printer.setFullPage(TRUE);
	
	if ( printer.setup( this ) )
	{
		QPainter p( &printer );
		
		if( !p.isActive() ) // starting printing failed
			return false;
		
		Q3PaintDeviceMetrics metrics(p.device());
		int dpiy = metrics.logicalDpiY();
		int margin = (int) ( (2/2.54)*dpiy ); // 2 cm margins
		QRect body( margin, margin, metrics.width() - 2*margin, metrics.height() - 2*margin );
		Q3SimpleRichText richText( text(),
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

#else
	QMessageBox::warning( this, 
		i18n( "%1 - could not print") . arg(APP_NAME),
		i18n( "Could not print.\nYour Qt library has been compiled without printing support");
	return false;

#endif
*/
}

void KCHMViewWindow_QTextBrowser::clipSelectAll( )
{
	selectAll();
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

QMenu * KCHMViewWindow_QTextBrowser::createPopupMenu( const QPoint & pos )
{
	/*FIXME
	QMenu * menu = getContextMenu( anchorAt( pos ), this );
	menu->exec( mapToGlobal( contentsToViewport( pos ) ) );
	*/
	return 0;
}

QVariant KCHMViewWindow_QTextBrowser::loadResource(int type, const QUrl & name)
{
	QString data, file, path = name.toString( QUrl::StripTrailingSlash );

	// Retreive the data from chm file
	LCHMFile * chm = ::mainWindow->chmFile();

	if ( !chm )
		return 0;

	int pos = path.find ('#');
	if ( pos != -1 )
		path = path.left (pos);
	
	path = makeURLabsolute( path, false );
	
	// To handle a single-image pages, we need to generate the HTML page to show 
	// this image. We did it in KCHMViewWindow::handleStartPageAsImage; now we need
	// to generate the HTML page, and set it.
	if ( LCHMUrlFactory::handleFileType( path, data ) )
		return QVariant( QString( data ) );
	
	if ( type == QTextDocument::HtmlResource || type == QTextDocument::StyleSheetResource )
	{
		if ( !chm->getFileContentAsString( &data, path ) )
			qWarning( "Could not resolve file %s\n", path.ascii() );
		
		return QVariant( QString( data ) );
	}
	else if ( type == QTextDocument::ImageResource )
	{
		QImage img;
		QByteArray buf;
		
		QString fpath = decodeUrl( path );
		
		if ( chm->getFileContentAsBinary( &buf, fpath ) )
		{
			if ( !img.loadFromData ( (const uchar *) buf.data(), buf.size() ) )
				qWarning( "Could not resolve file %s\n", path.ascii() );
		}
		
		return QVariant( img );
	}
	
	qWarning("loadResource: Unknown type %d", type);
	return QVariant();
}

void KCHMViewWindow_QTextBrowser::find(const QString & text, int flags)
{
	m_searchText = text;
	m_flags = flags;
	
	find( false, false );
}

void KCHMViewWindow_QTextBrowser::onFindNext()
{
	find( true, false );
}

void KCHMViewWindow_QTextBrowser::onFindPrevious()
{
	find( false, true );
}

void KCHMViewWindow_QTextBrowser::find( bool forward, bool backward )
{
	QTextDocument *doc = document();
	QTextCursor c = textCursor();
	QTextDocument::FindFlags options;
	
	::mainWindow->viewWindowMgr()->indicateFindResultStatus( KCHMViewWindowMgr::SearchResultFound );
	
	if ( c.hasSelection() )
		c.setPosition( forward ? c.position() : c.anchor(), QTextCursor::MoveAnchor );
	
	QTextCursor newCursor = c;
	
	if ( !m_searchText.isEmpty() )
	{
		if ( backward )
			options |= QTextDocument::FindBackward;
		
		if ( m_flags & SEARCH_CASESENSITIVE )
			options |= QTextDocument::FindCaseSensitively;
		
		if ( m_flags & SEARCH_WHOLEWORDS )
			options |= QTextDocument::FindWholeWords;
		
		newCursor = doc->find( m_searchText, c, options );
		
		if ( newCursor.isNull() )
		{
			QTextCursor ac( doc );
			ac.movePosition( options & QTextDocument::FindBackward 
			                 ? QTextCursor::End : QTextCursor::Start );
			newCursor = doc->find( m_searchText, ac, options );
			if ( newCursor.isNull() )
			{
				::mainWindow->viewWindowMgr()->indicateFindResultStatus( KCHMViewWindowMgr::SearchResultNotFound );
				newCursor = c;
			} 
			else
				::mainWindow->viewWindowMgr()->indicateFindResultStatus( KCHMViewWindowMgr::SearchResultFoundWrapped );
		}
	}
	
	setTextCursor( newCursor );
}
