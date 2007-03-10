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

#include <qcstring.h>
#include <qimage.h>
#include <qdir.h>

#include "libchmfile.h"
#include "libchmurlfactory.h"

#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmsourcefactory.h"

KCHMSourceFactory::KCHMSourceFactory (KCHMViewWindow * viewwindow)
	: QMimeSourceFactory()
{
	m_viewWindow = viewwindow;
}


const QMimeSource * KCHMSourceFactory::data( const QString & abs_name ) const
{
	QString data, file, path = abs_name;

	// Retreive the data from chm file
	 LCHMFile * chm = ::mainWindow->chmFile();

	if ( !chm )
		return 0;
	
	int pos = path.find ('#');
	if ( pos != -1 )
		path = path.left (pos);
	
	// To handle a single-image pages, we need to generate the HTML page to show 
	// this image. We did it in KCHMViewWindow::handleStartPageAsImage; now we need
	// to generate the HTML page, and set it.
	if ( LCHMUrlFactory::handleFileType( path, data ) )
	{
		((QMimeSourceFactory*)this)->setText (path, data);
	}
	else if ( path.endsWith (".htm") || path.endsWith (".html") )
	{
		if ( chm->getFileContentAsString( &data, path ) )
			((QMimeSourceFactory*)this)->setText (path, data);
	}
	else
	{
		// treat as image
		QImage img;
		QByteArray buf;
		
		if ( chm->getFileContentAsBinary( &buf, path ) )
		{
			if ( img.loadFromData ( (const uchar *) buf.data(), buf.size() ) )
				((QMimeSourceFactory*)this)->setImage (path, img);
		}
		else
		{
			((QMimeSourceFactory*)this)->setImage( path, img );
			qWarning( "Could not resolve file %s\n", path.ascii() );
		}
	}
	
	return QMimeSourceFactory::data (path);
}

QString KCHMSourceFactory::makeAbsolute ( const QString & abs_or_rel_name, const QString & ) const
{
	return m_viewWindow->makeURLabsolute ( abs_or_rel_name, false );
}
