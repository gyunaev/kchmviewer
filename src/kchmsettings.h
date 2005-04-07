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
#ifndef KCHMSETTINGS_H
#define KCHMSETTINGS_H

#include <qstring.h>
#include <qvaluelist.h>


/**
@author Georgy Yunaev
*/
class SavedBookmark;

class KCHMSettings
{
public:
    KCHMSettings ();
	
	bool	loadSettings (const QString& filename);
	bool	saveSettings ( );
	
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
	QString						m_patternfile;
};

#endif
