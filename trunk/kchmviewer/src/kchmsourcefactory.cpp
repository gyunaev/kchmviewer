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


//TODO: if an image or a CHM file is absent, generate an empty image/file
const QMimeSource * KCHMSourceFactory::data( const QString & abs_name ) const
{
	QString file, path;
	CHMFile * chm;

	// Retreive the data from chm file
	if ( KCHMViewWindow::isNewChmURL( abs_name, file, path ) )
		chm = ::mainWindow->getChmFile()->getCHMfilePointer( file );
	else
		chm = ::mainWindow->getChmFile();

	if ( !chm )
		return 0;
	
	if ( abs_name.endsWith (".htm") || abs_name.endsWith (".html") )
	{
		QString data;
		chm->GetFileContentAsString (data, abs_name);
		((QMimeSourceFactory*)this)->setText (abs_name, data);
	}
	else if ( m_viewWindow->areImagesResolved() )
	{
		// treat as image
		chmUnitInfo ui;
		
		if ( chm->ResolveObject (abs_name, &ui) )
		{
			QByteArray buf (ui.length);
			
			if ( chm->RetrieveObject (&ui, (unsigned char*) buf.data(), 0, ui.length) )
			{
				QImage img;
				
				if ( img.loadFromData ( (const uchar *) buf.data(), ui.length) )
					((QMimeSourceFactory*)this)->setImage (abs_name, img);
			}
			else
				fprintf (stderr, "Could not retrieve %s\n", abs_name.ascii());
		}
		else
			fprintf (stderr, "Could not resolve %s\n", abs_name.ascii());
	}
	else
		return 0;
	
	return QMimeSourceFactory::data (abs_name);
}

QString KCHMSourceFactory::makeAbsolute ( const QString & abs_or_rel_name, const QString & ) const
{
	return m_viewWindow->makeURLabsolute ( abs_or_rel_name, false );
}
