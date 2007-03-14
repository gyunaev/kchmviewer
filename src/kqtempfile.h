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

#ifndef KQTEMPFILE_H
#define KQTEMPFILE_H

#include <qvaluevector.h>
#include <qfile.h>

/*
 * This class generates temp file names in race condition-safe way,
 * returns QFile and filename pairs, keeps the track of opened temp files,
 * and deletes them when program exist.
 */

class KQTempFileKeeper
{
	public:
		KQTempFileKeeper();
		~KQTempFileKeeper();
		
		//! Generates a temporary file name, and creates it on disk at the same time.
		//! Returns the file. If tempdir is not empty, it is used as temp directory.
		bool	generateTempFile( QFile& file, const QString& tempdir = QString::null );
		
		//! Closes and removes all the files from disk
		void	destroyTempFiles();
		
	private:
		QValueVector<QString>	m_tempFiles;
		QString					m_tempDir;
		unsigned int			m_fileNumber;
};

#endif /* KQTEMPFILE_H */