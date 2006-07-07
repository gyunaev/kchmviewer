/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "kqtempfile.h"


KQTempFileKeeper::KQTempFileKeeper( )
{
#if defined(WIN32)
	m_tempDir = ::GetTempDirectory();
#else
	if ( getenv("TEMP") )
		m_tempDir = getenv("TEMP");
	else if ( getenv("TMP") )
		m_tempDir = getenv("TMP");
	else
		m_tempDir = "/tmp";
#endif

	m_fileNumber = 1;
}

KQTempFileKeeper::~ KQTempFileKeeper( )
{
	destroyTempFiles();
}

bool KQTempFileKeeper::generateTempFile( QFile & file, const QString & tempdir )
{
	QString usetempdir = ((tempdir != QString::null) ? tempdir : m_tempDir) + "/";
	
	while( 1 )
	{
		char fnbuf[128];
		sprintf( fnbuf, "KQTEMPFILE%d-%d-%d.tmp", (int) getpid(), (int) time(0), m_fileNumber++ );
				
		file.setName( usetempdir + fnbuf );
		if ( file.open( IO_WriteOnly ) )
			break;
	}
	
	return true;
}

void KQTempFileKeeper::destroyTempFiles( )
{
	for ( unsigned int i = 0; i < m_tempFiles.size(); i++ )
		QFile::remove( m_tempFiles[i] );
}
