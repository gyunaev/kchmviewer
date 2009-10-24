/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
 *   Please do not use email address above for bug reports; see            *
 *   the README file                                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
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
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.         *
 ***************************************************************************/

// Only compile this file if Qt WEBKIT is present
#if defined (QT_WEBKIT_LIB)

#include <QPrinter>
#include <QPrintDialog>

#include <QWebView>
#include <QWebFrame>  
#include <QNetworkReply> 
#include <QNetworkRequest> 

#include "kde-qt.h"
#include "libchmurlfactory.h"
#include "kchmconfig.h"
#include "kchmmainwindow.h"
#include "kchmviewwindowmgr.h"
#include "kchmviewwindow_qtwebkit.h"


//
// A network reply to emulate data transfer from CHM file
//
class KCHMNetworkReply : public QNetworkReply
{
	public:
		KCHMNetworkReply( const QNetworkRequest &request, const QUrl &url )
		{
			setRequest( request );
			setOpenMode( QIODevice::ReadOnly );
			
			m_data = loadResource( url );
			m_length = m_data.length();
		
			setHeader( QNetworkRequest::ContentLengthHeader, QByteArray::number(m_data.length()) );
			QTimer::singleShot( 0, this, SIGNAL(metaDataChanged()) );
			QTimer::singleShot( 0, this, SIGNAL(readyRead()) );
		}

		virtual qint64 bytesAvailable() const 
		{ 
			return m_data.length() + QNetworkReply::bytesAvailable();
		}
		
		virtual void abort()
		{
		}

	protected:
		virtual qint64 readData(char *buffer, qint64 maxlen)
		{
			qint64 len = qMin(qint64(m_data.length()), maxlen);
			if (len)
			{
				qMemCopy(buffer, m_data.constData(), len);
				m_data.remove(0, len);
			}
			
			if (!m_data.length())
				QTimer::singleShot(0, this, SIGNAL(finished()));
			return len;
		}

		QByteArray loadResource( const QUrl &url )
		{
			QString data, file, path = url.path(); //toString( QUrl::StripTrailingSlash );

			// Retreive the data from chm file
			LCHMFile * chm = ::mainWindow->chmFile();

			if ( !chm )
				return QByteArray();

			int pos = path.indexOf('#');
			if ( pos != -1 )
				path = path.left (pos);
		
			// To handle a single-image pages, we need to generate the HTML page to show 
			// this image. We did it in KCHMViewWindow::handleStartPageAsImage; now we need
			// to generate the HTML page, and set it.
			if ( LCHMUrlFactory::handleFileType( path, data ) )
				return qPrintable( data );
	
			QByteArray buf;
			
			if ( path.endsWith( ".html", Qt::CaseInsensitive ) 
			|| path.endsWith( ".htm", Qt::CaseInsensitive ) )
			{
				// If encoding autodetection is enabled, decode it. Otherwise pass as binary.
				if ( appConfig.m_advAutodetectEncoding )
				{
					if ( !chm->getFileContentAsString( &data, path ) )
						qWarning( "Could not resolve file %s\n", qPrintable( path ) );
		
					setHeader( QNetworkRequest::ContentTypeHeader, "text/html" );
					buf = qPrintable( data );
				}
				else
				{
					if ( !chm->getFileContentAsBinary( &buf, path ) )
						qWarning( "Could not resolve file %s\n", qPrintable( path ) );
		
					setHeader( QNetworkRequest::ContentTypeHeader, "text/html" );
				}
			}
			else
			{
				QString fpath = KCHMViewWindow_QtWebKit::decodeUrl( path );
		
				if ( !chm->getFileContentAsBinary( &buf, fpath ) )
					qWarning( "Could not resolve file %s\n", qPrintable( path ) );
		
				setHeader( QNetworkRequest::ContentTypeHeader, "binary/octet" );
			}
			
			return buf;			
		}
		
	private:
		QByteArray	m_data;
		qint64 		m_length;
};


//
// A network manager to emulate data transfer from CHM file
//
class KCHMNetworkAccessManager : public QNetworkAccessManager
{
	public:
		KCHMNetworkAccessManager( QObject *parent )
			: QNetworkAccessManager(parent)
		{
		}

	protected:
		virtual QNetworkReply *createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoingData = 0)
		{
			const QString scheme = request.url().scheme();
			
			if ( scheme == QLatin1String("ms-its") )
				return new KCHMNetworkReply( request, request.url() );

			return QNetworkAccessManager::createRequest(op, request, outgoingData);
		}
};




//
// Webkit browser
//
KCHMViewWindow_QtWebKit::KCHMViewWindow_QtWebKit( QTabWidget * parent )
	: QWebView ( parent ), KCHMViewWindow ( parent )
{
	m_zoomfactor = 1;
	invalidate();
	
	page()->setNetworkAccessManager(new KCHMNetworkAccessManager(this));
		
	page()->setLinkDelegationPolicy( QWebPage::DelegateAllLinks );
	connect( this, SIGNAL( linkClicked ( const QUrl& ) ), this, SLOT( onAnchorClicked ( const QUrl& ) ) );
}


KCHMViewWindow_QtWebKit::~KCHMViewWindow_QtWebKit()
{
}


bool KCHMViewWindow_QtWebKit::openPage (const QString& url)
{
	if ( m_allowSourceChange )
	{
		// Do URI decoding, qtextbrowser does stupid job.
		QString fixedname = decodeUrl( url );
		
		if ( !fixedname.startsWith( "ms-its://" ) )
			fixedname = "ms-its://" + fixedname;
		
		setUrl( fixedname );
	}
	else
		m_allowSourceChange = true;

	return true;
}


void KCHMViewWindow_QtWebKit::setZoomFactor( int zoom )
{
	m_zoomfactor = zoom;
	setTextSizeMultiplier ( 1.0 + m_zoomfactor * 0.5 );
}

void KCHMViewWindow_QtWebKit::invalidate( )
{
	m_zoomfactor = 1;
	m_allowSourceChange = true;
	setTextSizeMultiplier( 1.0 );
	reload();
	
	KCHMViewWindow::invalidate( );
}

int KCHMViewWindow_QtWebKit::getScrollbarPosition( )
{
	return page()->currentFrame()->scrollBarValue( Qt::Vertical );
}

void KCHMViewWindow_QtWebKit::setScrollbarPosition( int pos )
{
	page()->currentFrame()->setScrollBarValue( Qt::Vertical, pos );
}

void KCHMViewWindow_QtWebKit::addZoomFactor( int value )
{
	setZoomFactor( m_zoomfactor + value );
}

void KCHMViewWindow_QtWebKit::onAnchorClicked(const QUrl & url)
{
	emit linkClicked( url.path(), m_allowSourceChange );
}


bool KCHMViewWindow_QtWebKit::printCurrentPage( )
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


void KCHMViewWindow_QtWebKit::clipSelectAll( )
{
	QMessageBox::information( 0, "Not implemented", "Not implemented" );
//	selectAll();
}


void KCHMViewWindow_QtWebKit::clipCopy( )
{
	triggerPageAction( QWebPage::Copy );
}


// Shamelessly stolen from Qt
QString KCHMViewWindow_QtWebKit::decodeUrl( const QString &input )
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


QMenu * KCHMViewWindow_QtWebKit::createPopupMenu( const QPoint & pos )
{
	QMenu * menu = getContextMenu( anchorAt( pos ), this );
	menu->exec( pos );

	return 0;
}


void KCHMViewWindow_QtWebKit::find(const QString & text, int flags)
{
	m_searchText = text;
	m_flags = flags;
	
	find( false, false );
}

void KCHMViewWindow_QtWebKit::onFindNext()
{
	find( true, false );
}

void KCHMViewWindow_QtWebKit::onFindPrevious()
{
	find( false, true );
}

void KCHMViewWindow_QtWebKit::find( bool , bool backward )
{
	QWebPage::FindFlags flags = QWebPage::FindWrapsAroundDocument;
	
	if ( backward )
		flags |= QWebPage::FindBackward;
	
	if ( m_flags & SEARCH_CASESENSITIVE )
		flags |= QWebPage::FindCaseSensitively;
	
	if ( findText( m_searchText, flags ) )
		::mainWindow->viewWindowMgr()->indicateFindResultStatus( KCHMViewWindowMgr::SearchResultFound );
	else
		::mainWindow->viewWindowMgr()->indicateFindResultStatus( KCHMViewWindowMgr::SearchResultNotFound );
}

void KCHMViewWindow_QtWebKit::contextMenuEvent(QContextMenuEvent * e)
{
	// From Qt Assistant
	QMenu *m = new QMenu(0);
	QString link = anchorAt( e->pos() );
	
	if ( !link.isEmpty() )
	{
		m->addAction( i18n("Open Link in a new tab\tShift+LMB"), ::mainWindow, SLOT( onOpenPageInNewTab() ) );
		m->addAction( i18n("Open Link in a new background tab\tCtrl+LMB"), ::mainWindow, SLOT( onOpenPageInNewBackgroundTab() ) );
		m->addSeparator();
		m_newTabLinkKeeper = link;
	}
	
	::mainWindow->setupPopupMenu( m );
	m->exec( e->globalPos() );
	delete m;
}

QString KCHMViewWindow_QtWebKit::anchorAt(const QPoint & pos)
{
	QWebHitTestResult res = page()->currentFrame()->hitTestContent( pos );
	
	if ( !res.linkUrl().isValid() )
		return QString::null;
	
	return  res.linkUrl().path();
}

#endif // #if defined (QT_WEBKIT_LIB)

