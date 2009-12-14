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

#include <QPrinter>
#include <QPrintDialog>

#include "libchmurlfactory.h"

#include "kde-qt.h"
#include "mainwindow.h"
#include "viewwindowmgr.h"
#include "viewwindow_qtextbrowser.h"


ViewWindow_QTextBrowser::ViewWindow_QTextBrowser( ViewWindowTabs * parent )
	: QTextBrowser ( parent ), ViewWindow ( parent )
{
	m_zoomfactor = 0;
	invalidate();
	
#if QT_VERSION >= 0x040300
	setOpenLinks( false );
#endif
	connect( this, SIGNAL( anchorClicked ( const QUrl& ) ), this, SLOT( onAnchorClicked ( const QUrl& ) ) );
}


ViewWindow_QTextBrowser::~ViewWindow_QTextBrowser()
{
}

bool ViewWindow_QTextBrowser::openPage (const QString& url)
{
	setSource (url);
	return true;
}

void ViewWindow_QTextBrowser::setSource ( const QUrl & name )
{
	if ( m_allowSourceChange )
	{
		// Do URI decoding, qtextbrowser does stupid job.
		QString fixedname = decodeUrl( name.toString() );
		QTextBrowser::setSource (fixedname);
	}
	else
		m_allowSourceChange = true;
}

void ViewWindow_QTextBrowser::setZoomFactor( int zoom )
{
	m_zoomfactor = zoom;
	
	if ( zoom < 0 )
		QTextBrowser::zoomOut( -zoom );
	else if ( zoom > 0 )
		QTextBrowser::zoomIn( zoom);
}

void ViewWindow_QTextBrowser::invalidate( )
{
	m_zoomfactor = 0;
	m_allowSourceChange = true;
	reload();
	
	ViewWindow::invalidate( );
}

int ViewWindow_QTextBrowser::getScrollbarPosition( )
{
	return verticalScrollBar()->sliderPosition();
}

void ViewWindow_QTextBrowser::setScrollbarPosition( int pos )
{
	verticalScrollBar()->setSliderPosition( pos);
}

void ViewWindow_QTextBrowser::addZoomFactor( int value )
{
	setZoomFactor( value);
}

void ViewWindow_QTextBrowser::onAnchorClicked(const QUrl & url)
{
#if QT_VERSION < 0x040300
	emit linkClicked( url.toString(), m_allowSourceChange );
#else
	bool q;
	emit linkClicked( url.toString(), q );
#endif
}


bool ViewWindow_QTextBrowser::printCurrentPage( )
{
	QPrinter printer( QPrinter::HighResolution );
	//printer.setFullPage(true);
	
	QPrintDialog dlg( &printer, this );
	
	if ( dlg.exec() != QDialog::Accepted )
	{
		::mainWindow->showInStatusBar( i18n( "Printing aborted") );
		return false;
	}

	document()->print( &printer );
	::mainWindow->showInStatusBar( i18n( "Printing finished") );
	return true;
}

void ViewWindow_QTextBrowser::clipSelectAll( )
{
	selectAll();
}

void ViewWindow_QTextBrowser::clipCopy( )
{
	copy ();
}


// Shamelessly stolen from Qt
QString ViewWindow_QTextBrowser::decodeUrl( const QString &input )
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

QMenu * ViewWindow_QTextBrowser::createPopupMenu( const QPoint & pos )
{
	QMenu * menu = getContextMenu( anchorAt( pos ), this );
	menu->exec( viewport()->mapToGlobal( pos ) );

	return 0;
}

QVariant ViewWindow_QTextBrowser::loadResource(int type, const QUrl & name)
{
	QString data, file, path = name.toString( QUrl::StripTrailingSlash );

	// Retreive the data from chm file
	LCHMFile * chm = ::mainWindow->chmFile();

	if ( !chm )
		return 0;

	int pos = path.indexOf('#');
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
			qWarning( "Needed file %s is not present in this CHM archive\n", qPrintable( path ) );

		// A "fix" (actually hack) for CHM files people sent to me. I have no idea why QTextBrowser cannot show it.
		if ( type == QTextDocument::HtmlResource )
			data.remove( "<META http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">" );

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
				qWarning( "Needed file %s is not present in this CHM archive\n", qPrintable( path ) );
		}
		
		return QVariant( img );
	}
	
	qWarning("loadResource: Unknown type %d", type);
	return QVariant();
}

void ViewWindow_QTextBrowser::find(const QString & text, int flags)
{
	m_searchText = text;
	m_flags = flags;
	
	find( false, false );
}

void ViewWindow_QTextBrowser::onFindNext()
{
	find( true, false );
}

void ViewWindow_QTextBrowser::onFindPrevious()
{
	find( false, true );
}

void ViewWindow_QTextBrowser::find( bool forward, bool backward )
{
	QTextDocument *doc = document();
	QTextCursor c = textCursor();
	QTextDocument::FindFlags options;
	
	::mainWindow->viewWindowMgr()->indicateFindResultStatus( ViewWindowMgr::SearchResultFound );
	
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
				::mainWindow->viewWindowMgr()->indicateFindResultStatus( ViewWindowMgr::SearchResultNotFound );
				newCursor = c;
			} 
			else
				::mainWindow->viewWindowMgr()->indicateFindResultStatus( ViewWindowMgr::SearchResultFoundWrapped );
		}
	}
	
	setTextCursor( newCursor );
}

void ViewWindow_QTextBrowser::contextMenuEvent(QContextMenuEvent * e)
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

void ViewWindow_QTextBrowser::mouseReleaseEvent ( QMouseEvent * event )
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

	QTextBrowser::mouseReleaseEvent( event );
}
