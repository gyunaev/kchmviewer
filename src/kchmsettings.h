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
#ifndef KCHMSETTINGS_H
#define KCHMSETTINGS_H

#include <qstring.h>
#include <qvaluelist.h>


/**
@author Georgy Yunaev
*/
class SavedBookmark;
class QFileInfo;


class KCHMSettings
{
public:
    KCHMSettings ();
	
	bool	loadSettings (const QString& filename);
	bool	saveSettings ( );
	void 	removeSettings ( const QString& filename );
	
	class SavedBookmark
	{
	public:
		SavedBookmark() { scroll_y = 0; }
		SavedBookmark (QString n, QString u, int y) : name(n), url(u), scroll_y(y) {};
		
		QString		name;
		QString		url;
		int			scroll_y;
	};

	typedef 	QValueList<QString>			search_saved_settings_t;
	typedef 	QValueList<SavedBookmark>	bookmark_saved_settings_t;
	
	QString						m_activepage;
	int							m_scrollbarposition;
	int							m_activetab;
	int							m_activeencodinglcid;
	int							m_chosenzoom;
	search_saved_settings_t		m_searchhistory;
	bookmark_saved_settings_t	m_bookmarks;

private:
	QString  getSettingsFilename ( const QString& filename );
	
	// params of current file
	QString						m_currentsettingsname;
	unsigned int				m_currentfiledate;
	unsigned int				m_currentfilesize;
};

#endif
