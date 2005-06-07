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

#include <qcstring.h>
#include <qimage.h>
#include <qdir.h>

#include "kchmmainwindow.h"
#include "kchmviewwindow.h"
#include "kchmsourcefactory.h"
#include "xchmfile.h"

KCHMSourceFactory::KCHMSourceFactory (KCHMViewWindow * viewwindow)
	: QMimeSourceFactory()
{
	m_viewWindow = viewwindow;
}


const QMimeSource * KCHMSourceFactory::data( const QString & abs_name ) const
{
	QString file, path = abs_name;
	CHMFile * chm;

	// Retreive the data from chm file
	if ( KCHMViewWindow::isNewChmURL( abs_name, file, path ) )
		chm = ::mainWindow->getChmFile()->getCHMfilePointer( file );
	else
		chm = ::mainWindow->getChmFile();

	if ( !chm )
		return 0;
	
	int pos = path.find ('#');
	if ( pos != -1 )
		path = path.left (pos);
	
	if ( path.endsWith (".htm") || path.endsWith (".html") )
	{
		QString data;
		chm->GetFileContentAsString (data, path);
		((QMimeSourceFactory*)this)->setText (path, data);
	}
	else
	{
		// treat as image
		chmUnitInfo ui;
		QImage img;
		
		if ( chm->ResolveObject (path, &ui) )
		{
			QByteArray buf (ui.length);
			
			if ( chm->RetrieveObject (&ui, (unsigned char*) buf.data(), 0, ui.length) )
			{
				if ( img.loadFromData ( (const uchar *) buf.data(), ui.length) )
					((QMimeSourceFactory*)this)->setImage (path, img);
			}
			else
				fprintf (stderr, "Could not retrieve %s\n", path.ascii());
		}
		else
		{
			((QMimeSourceFactory*)this)->setImage (path, img);
			fprintf (stderr, "Could not resolve %s\n", path.ascii());
		}
	}
	
	return QMimeSourceFactory::data (path);
}

QString KCHMSourceFactory::makeAbsolute ( const QString & abs_or_rel_name, const QString & ) const
{
	return m_viewWindow->makeURLabsolute ( abs_or_rel_name, false );
}