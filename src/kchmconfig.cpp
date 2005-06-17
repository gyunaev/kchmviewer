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

#include "kde-qt.h"
#include "kchmconfig.h"

KCHMConfig appConfig;

const char * APP_PATHINUSERDIR = ".kchmviewer";


KCHMConfig::KCHMConfig()
{
	QDir dir;
	m_datapath = QDir::homeDirPath() + "/" + APP_PATHINUSERDIR;
	 
	dir.setPath (m_datapath);
	
	if ( !dir.exists() && !dir.mkdir(m_datapath) )
		qWarning ("Could not create directory %s", m_datapath.ascii());

	m_LoadLatestFileOnStartup = false;
	m_onNewChmClick = ACTION_ASK_USER;
	m_onExternalLinkClick = ACTION_ASK_USER;
	m_HistorySize = 10;
	m_HistoryStoreExtra = true;
	
	m_QtBrowserPath = "viewurl-netscape.sh \"%s\"";
	m_kdeUseQTextBrowser = false;
	m_kdeEnableJS = false;
	m_kdeEnableJava = false;
	m_kdeEnablePlugins = true;
	m_kdeEnableRefresh = false;
}


KCHMConfig::~KCHMConfig()
{
}

bool KCHMConfig::load()
{
	QFile file (m_datapath + "/config");
	if ( !file.open (IO_ReadOnly) )
		return false; // no error message - not actually a problem
	
	QString line;
	bool getting_history = false;
	m_History.clear();
	
	while ( file.readLine ( line, 65535 ) > 0 )
	{
		line = line.stripWhiteSpace();
		
		// skip empty lines and comments
		if ( line.isEmpty() || line[0] == '#' )
			continue;
		
		QRegExp rxsection ("^\\[(\\w+)\\]$"), rxkeypair ("^(\\w+)\\s*=\\s*(.*)$");
		
		if ( rxsection.search ( line ) != -1 )
		{
			if ( rxsection.cap (1) == "settings" )
				getting_history = false;
			else if ( rxsection.cap (1) == "history" )
				getting_history = true;
			else
				qWarning ("Unknown configuration section: %s", rxsection.cap (1).ascii());
			
			continue;
		}
		else if ( !getting_history && rxkeypair.search ( line ) != -1 )
		{
			QString key (rxkeypair.cap (1)), value (rxkeypair.cap(2));
			
			if ( key == "LoadLatestFileOnStartup" )
				m_LoadLatestFileOnStartup = value.toInt() ? true : false;
			else if ( key == "onNewChmClick" )
				m_onNewChmClick = (choose_action_t) value.toInt();
			else if ( key == "onExternalLinkClick" )
				m_onExternalLinkClick = (choose_action_t) value.toInt();
			else if ( key == "HistorySize" )
				m_HistorySize = value.toInt();
			else if ( key == "HistoryStoreExtra" )
				m_HistoryStoreExtra = value.toInt() ? true : false;
			else if ( key == "QtBrowserPath" )
				m_QtBrowserPath = value;
			else if ( key == "kdeUseQTextBrowser" )
				m_kdeUseQTextBrowser = value.toInt() ? true : false;
			else if ( key == "kdeEnableJS" )
				m_kdeEnableJS = value.toInt() ? true : false;
			else if ( key == "kdeEnableJava" )
				m_kdeEnableJava = value.toInt() ? true : false;
			else if ( key == "kdeEnablePlugins" )
				m_kdeEnablePlugins = value.toInt() ? true : false;
			else if ( key == "kdeEnableRefresh" )
				m_kdeEnableRefresh = value.toInt() ? true : false;
			else
				qWarning ("Unknown key=value pair: %s", line.ascii());
		}
		else if ( getting_history )
		{
			if ( m_History.size() < m_HistorySize )
				m_History.push_back (line);
		}
		else
			qWarning ("Unknown line in configuration: %s", line.ascii());
	}

	return true;
}

bool KCHMConfig::save( )
{
	QFile file (m_datapath + "/config");
	if ( !file.open (IO_WriteOnly) )
	{
		qWarning ("Could not write settings into file %s: %s", file.name().ascii(), file.errorString().ascii());
		return false;
	}
	
	QTextStream stream( &file );
	stream << "[settings]\n";
	stream << "LoadLatestFileOnStartup=" << m_LoadLatestFileOnStartup << "\n";

	stream << "onNewChmClick=" << m_onNewChmClick << "\n";
	stream << "onExternalLinkClick=" << m_onExternalLinkClick << "\n";
	stream << "HistorySize=" << m_HistorySize << "\n";
	stream << "HistoryStoreExtra=" << m_HistoryStoreExtra << "\n";

	stream << "QtBrowserPath=" << m_QtBrowserPath << "\n";
	stream << "kdeUseQTextBrowser=" << m_kdeUseQTextBrowser << "\n";
	stream << "kdeEnableJS=" << m_kdeEnableJS << "\n";
	stream << "kdeEnableJava=" << m_kdeEnableJava << "\n";
	stream << "kdeEnablePlugins=" << m_kdeEnablePlugins << "\n";
	stream << "kdeEnableRefresh=" << m_kdeEnableRefresh << "\n";

	stream << "\n[history]\n";
	
	// Do not write all the history, but only the needed amount
	for ( unsigned int i = 0; i < m_History.size(); i++ )
		stream << m_History[m_History.size() - 1 - i] << "\n";
	
	//	m_History
	return true;
}
