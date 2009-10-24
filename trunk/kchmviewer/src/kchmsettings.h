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

#ifndef KCHMSETTINGS_H
#define KCHMSETTINGS_H

#include <QString>
#include <QList>


class KCHMSettings
{
	public:
		KCHMSettings ();
		
		bool	loadSettings (const QString& filename);
		bool	saveSettings ( );
		void 	removeSettings ( const QString& filename );
		
		QString	searchIndexFile() const	{ return m_searchIndex; }
		
		class SavedBookmark
		{
		public:
			SavedBookmark() { scroll_y = 0; }
			SavedBookmark ( const QString& n, const QString& u, int y) : name(n), url(u), scroll_y(y) {};
			
			QString		name;
			QString		url;
			int			scroll_y;
		};
	
		class SavedViewWindow
		{
			public:
				SavedViewWindow() { scroll_y = 0; zoom = 0; }
				SavedViewWindow ( const QString& u, int y, int z) : url(u), scroll_y(y), zoom(z) {};
			
				QString		url;
				int			scroll_y;
				int			zoom;
		};
		
		typedef QList<QString>			search_saved_settings_t;
		typedef QList<SavedBookmark>	bookmark_saved_settings_t;
		typedef QList<SavedViewWindow>	viewindow_saved_settings_t;
		
		int							m_window_size_x;
		int							m_window_size_y;
		int							m_window_size_splitter;
		int							m_activetabsystem;
		int							m_activetabwindow;
		QString						m_activeEncoding;
		search_saved_settings_t		m_searchhistory;
		bookmark_saved_settings_t	m_bookmarks;
		viewindow_saved_settings_t	m_viewwindows;
	
	private:
		void		getFilenames(const QString & helpfilename, QString * settingsfile, QString * indexfile );
		
		unsigned int				m_currentfilesize;
		unsigned int				m_currentfiledate;
		QString						m_settingsFile;
		QString						m_searchIndex;
};

#endif
