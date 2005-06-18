
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

#include <qfile.h>
#include <qfileinfo.h>
#include <qdatastream.h>
 
#include "kchmsettings.h"
#include "kchmconfig.h"

static Q_INT32 SETTINGS_MAGIC = 0x98AB4E7C;
static Q_INT32 SETTINGS_VERSION = 3;

/*
 * The order is important!
 * To be compatible with next versions, you may add items ONLY before the MARKER_END!
 */
enum marker_t
{
	MARKER_FILESIZE = 1,
	MARKER_FILETIME,
	MARKER_ACTIVEPAGE,
	MARKER_SCROLLBARPOSITION,
	MARKER_ACTIVETAB,
	MARKER_ACTIVEENCODING,
	MARKER_SEARCHHISTORY,
	MARKER_BOOKMARKS,
	MARKER_CHOSENZOOM,

	// This should be the last
	MARKER_END = 0x7FFF
};

// Helpers for serialization of SavedBookmark through QDataStream
static inline QDataStream& operator<< ( QDataStream& s, const KCHMSettings::SavedBookmark& b )
{
	s << b.name;
	s << b.url;
	s << b.scroll_y;
	return s;
}

static inline QDataStream& operator>> ( QDataStream& s, KCHMSettings::SavedBookmark& b )
{
	s >> b.name;
	s >> b.url;
	s >> b.scroll_y;
	return s;
}


KCHMSettings::KCHMSettings( )
{
	m_scrollbarposition = 0;
	m_activetab = 0;
	m_activeencodinglcid = 0;
	m_chosenzoom = 0;
}


bool KCHMSettings::loadSettings( const QString & filename )
{
	m_activepage = QString::null;
	m_scrollbarposition = 0;
	m_activetab = 0;
	m_activeencodinglcid = 0;
	m_searchhistory.clear();
	m_bookmarks.clear();

	QFileInfo finfo ( filename );

	if ( !finfo.size() )
		return false;
	
	m_currentsettingsname = getSettingsFilename( filename );
	
	if ( m_currentsettingsname.isEmpty() )
		return false;

	QFile file( m_currentsettingsname );

    if ( !file.open (IO_ReadOnly) )
		return false; // it's ok, file may not exist
	
    QDataStream stream (&file);

	// Read and check header
	Q_INT32 data;
	bool complete_read = false;
	stream >> data; // magic
	
	if ( data != SETTINGS_MAGIC )
	{
		qWarning ("file %s has bad magic value, ignoring it.", file.name().ascii());
		return false;
	}
	
	stream >> data; // version
	if ( data > SETTINGS_VERSION )
	{
		qWarning ("file %s has unsupported data version %d,  ignoring it.", file.name().ascii(), data);
		return false;
	}

	// Read everything by marker
	while ( 1 )
	{
		stream >> data; // marker
		if ( data == MARKER_END )
		{
			complete_read = true;
			break;
		}
		
		switch (data)
		{
		case MARKER_FILESIZE:
			stream >> m_currentfilesize;
			if ( m_currentfilesize != finfo.size() )
			{
				m_currentfilesize = finfo.size();
				return false;
			}
			break;
			
		case MARKER_FILETIME:
			stream >> m_currentfiledate;
			if ( m_currentfiledate != finfo.lastModified().toTime_t() )
			{
				m_currentfiledate = finfo.lastModified().toTime_t();
				return false;
			}
			break;
			
		case MARKER_ACTIVEPAGE:
			stream >> m_activepage;
			break;
	
		case MARKER_SCROLLBARPOSITION:
			stream >> m_scrollbarposition;
			break;
			
		case MARKER_ACTIVETAB:
			stream >> m_activetab;
			break;
	
		case MARKER_ACTIVEENCODING:
			stream >> m_activeencodinglcid;
			break;
	
		case MARKER_SEARCHHISTORY:
			stream >> m_searchhistory;
			break;
	
		case MARKER_BOOKMARKS:
			stream >> m_bookmarks;
			break;

		case MARKER_CHOSENZOOM:
			stream >> m_chosenzoom;
			break;
		}
	}
	
	return complete_read;
}


bool KCHMSettings::saveSettings( )
{
	QFile file( m_currentsettingsname );
    if ( !file.open (IO_WriteOnly) )
	{
		qWarning ("Could not write settings into file %s: %s", file.name().ascii(), file.errorString().ascii());
		return false;
	}
	
    QDataStream stream (&file);

	// Save header
	stream << SETTINGS_MAGIC;
	stream << SETTINGS_VERSION;

	// Save size and last-modified
	stream << MARKER_FILESIZE;
	stream << m_currentfilesize;
	stream << MARKER_FILETIME;
	stream << m_currentfiledate;
	
	// Save generic settings
	stream << MARKER_ACTIVEPAGE;
	stream << m_activepage;
	
	stream << MARKER_SCROLLBARPOSITION;
	stream << m_scrollbarposition;
	
	stream << MARKER_ACTIVETAB;
	stream << m_activetab;
	
	stream << MARKER_ACTIVEENCODING;
	stream << m_activeencodinglcid;
	
	// Save search history vector
	stream << MARKER_SEARCHHISTORY;
	stream << m_searchhistory;
	
	stream << MARKER_BOOKMARKS;
	stream << m_bookmarks;

	stream << MARKER_CHOSENZOOM;
	stream << m_chosenzoom;
	
	stream << MARKER_END;
	return true;
}

QString KCHMSettings::getSettingsFilename( const QString & filename )
{
	// Create a filename for help storage: name-size-lastmodified.kchmviewer
	QFileInfo finfo ( filename );

	if ( !finfo.size() )
		return QString::null;
		
	return appConfig.m_datapath + "/" + finfo.baseName() + ".kchmviewer";
}

void KCHMSettings::removeSettings( const QString & filename )
{
	QFile::remove ( getSettingsFilename ( filename ) );
}
