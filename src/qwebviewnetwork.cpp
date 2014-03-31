/**************************************************************************
 *  Kchmviewer - a portable CHM file viewer with the best support for     *
 *  the international languages                                           *
 *                                                                        *
 *  Copyright (C) 2004-2012 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  Please read http://www.kchmviewer.net/reportbugs.html if you want     *
 *  to report a bug. It lists things I need to fix it!                    *
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

#include <QDir>

#include "helper_urlfactory.h"

#include "qwebviewnetwork.h"
#include "viewwindow.h"
#include "config.h"
#include "mainwindow.h"


KCHMNetworkReply::KCHMNetworkReply( const QNetworkRequest &request, const QUrl &url )
{
	setRequest( request );
	setOpenMode( QIODevice::ReadOnly );

	m_data = loadResource( url );
	m_length = m_data.length();

	setHeader( QNetworkRequest::ContentLengthHeader, QByteArray::number(m_data.length()) );
	QMetaObject::invokeMethod(this, "metaDataChanged", Qt::QueuedConnection);

	if ( m_length )
		QMetaObject::invokeMethod(this, "readyRead", Qt::QueuedConnection);

	QMetaObject::invokeMethod(this, "finished", Qt::QueuedConnection);
}

qint64 KCHMNetworkReply::bytesAvailable() const
{
	return m_data.length() + QNetworkReply::bytesAvailable();
}

void KCHMNetworkReply::abort()
{
}

qint64 KCHMNetworkReply::readData(char *buffer, qint64 maxlen)
{
	qint64 len = qMin(qint64(m_data.length()), maxlen);

	if (len)
	{
		qMemCopy(buffer, m_data.constData(), len);
		m_data.remove(0, len);
	}

	return len;
}

QByteArray KCHMNetworkReply::loadResource( const QUrl &url )
{
	QString data, file, path = url.toString( QUrl::StripTrailingSlash );

	// Retreive the data from chm file
	EBook * chm = ::mainWindow->chmFile();

	// Does the file have a file name, or just a path with ms-its prefix?
	if ( !path.contains( "::" ) )
	{
		// Just the prefix, so strip it
		path.remove( 0, 7 );
	}
	else if ( path.startsWith( "ms-its:", Qt::CaseInsensitive ) )
	{
		// A broken? implementation inserts mandatory / path before the file name here. Remove it.
		if ( path[7] == '/' )
			path.remove( 7, 1 );

		if ( HelperUrlFactory::isNewChmURL ( path, mainWindow->getOpenedFileName(), file, data) )
		{
			EBook * newchm = EBook::loadFile( file );

			if ( !newchm )
			{
				qWarning( "External resource %s cannot be loaded from file %s\n", qPrintable( data ), qPrintable( file ) );
				return QByteArray();
			}

			chm = newchm;
			path = data;
		}
	}

	if ( !chm )
		return QByteArray();

	int pos = path.indexOf('#');
	if ( pos != -1 )
		path = path.left (pos);

	// To handle a single-image pages, we need to generate the HTML page to show
	// this image. We did it in KCHMViewWindow::handleStartPageAsImage; now we need
	// to generate the HTML page, and set it.
	if ( HelperUrlFactory::handleFileType( path, data ) )
		return qPrintable( data );

	QByteArray buf;

	if ( path.endsWith( ".html", Qt::CaseInsensitive )
	|| path.endsWith( ".htm", Qt::CaseInsensitive ) )
	{
		// If encoding autodetection is enabled, decode it. Otherwise pass as binary.
		if ( pConfig->m_advAutodetectEncoding )
		{
			if ( !chm->getFileContentAsString( data, path ) )
				qWarning( "Could not resolve file %s\n", qPrintable( path ) );

			setHeader( QNetworkRequest::ContentTypeHeader, "text/html" );
			buf = qPrintable( data );
		}
		else
		{
			if ( !chm->getFileContentAsBinary( buf, path ) )
				qWarning( "Could not resolve file %s\n", qPrintable( path ) );

			setHeader( QNetworkRequest::ContentTypeHeader, "text/html" );
		}
	}
	else
	{
		QString fpath = ViewWindow::decodeUrl( path );

		if ( !chm->getFileContentAsBinary( buf, fpath ) )
			qWarning( "Could not resolve file %s\n", qPrintable( path ) );

		setHeader( QNetworkRequest::ContentTypeHeader, "binary/octet" );
	}

	return buf;
}


KCHMNetworkAccessManager::KCHMNetworkAccessManager( QObject *parent )
	: QNetworkAccessManager(parent)
{
}

QNetworkReply * KCHMNetworkAccessManager::createRequest( Operation op, const QNetworkRequest &request, QIODevice *outgoingData )
{
	const QString scheme = request.url().scheme();

	if ( scheme == QLatin1String("ms-its") )
		return new KCHMNetworkReply( request, request.url() );

	if ( pConfig->m_browserEnableRemoteContent )
		return QNetworkAccessManager::createRequest( op, request, outgoingData );
	else
		return QNetworkAccessManager::createRequest( QNetworkAccessManager::GetOperation, QNetworkRequest(QUrl()) );
}
