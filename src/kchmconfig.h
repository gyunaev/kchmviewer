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

#ifndef KCHMCONFIG_H
#define KCHMCONFIG_H

#include <QString>
#include <QStringList>

extern const char * APP_PATHINUSERDIR;


/**
@author Georgy Yunaev
*/
class KCHMConfig
{
public:
	enum choose_action_t
	{
		ACTION_ALWAYS_OPEN,
		ACTION_ASK_USER,
		ACTION_DONT_OPEN
	};
	
	enum use_search_engine
	{
		SEARCH_USE_CHM,
  		SEARCH_USE_MINE,
	};
	
    KCHMConfig();
	~KCHMConfig();
	
	bool	load();
	bool	save();

	void	addFileToHistory ( const QString& file );
			
public:
	QString				m_datapath;
	QString				m_lastOpenedDir;
	
	bool				m_LoadLatestFileOnStartup;
	choose_action_t		m_onNewChmClick;
	choose_action_t		m_onExternalLinkClick;
	int					m_HistorySize;
	bool				m_HistoryStoreExtra;
	use_search_engine	m_useSearchEngine;
			
	QString				m_QtBrowserPath;
	bool				m_kdeUseQTextBrowser;
	bool				m_kdeEnableJS;
	bool				m_kdeEnableJava;
	bool				m_kdeEnablePlugins;
	bool				m_kdeEnableRefresh;
	
	bool				m_advUseInternalEditor;
	QString				m_advExternalEditorPath;
	
	QStringList			m_History;
};

extern KCHMConfig appConfig;

#endif
