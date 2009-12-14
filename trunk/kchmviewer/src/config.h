/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
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

#ifndef CONFIG_H
#define CONFIG_H

#include <QString>
#include <QStringList>

extern const char * APP_PATHINUSERDIR;


class Config
{
	public:
		enum choose_action_t
		{
			ACTION_ALWAYS_OPEN,
			ACTION_ASK_USER,
			ACTION_DONT_OPEN
		};
		
		enum UsedBrowser
		{
			BROWSER_QTEXTBROWSER = 0,
   			BROWSER_KHTMLPART,
	  		BROWSER_QTWEBKIT
		};
		
		Config();
		~Config();
		
		bool	load();
		bool	save();
	
		void	addRecentFile( const QString& file );
				
	public:
		QString				m_datapath;
		QString				m_lastOpenedDir;
		
		bool				m_LoadLatestFileOnStartup;
		choose_action_t		m_onNewChmClick;
		choose_action_t		m_onExternalLinkClick;
		int					m_numOfRecentFiles;
		bool				m_HistoryStoreExtra;
		int					m_usedBrowser;
		
		bool				m_kdeEnableJS;
		bool				m_kdeEnableJava;
		bool				m_kdeEnablePlugins;
		bool				m_kdeEnableRefresh;
		
		bool				m_advUseInternalEditor;
		QString				m_advExternalEditorPath;
		bool				m_advLayoutDirectionRL;
		bool				m_advAutodetectEncoding;
		
		QStringList			m_recentFiles;
};

extern Config appConfig;

#endif
