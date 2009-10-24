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

#include <QTextStream>

#include "kde-qt.h"
#include "kchmconfig.h"
#include "kchmsettings.h"
#include "kchmmainwindow.h"


KCHMConfig appConfig;

const char * APP_PATHINUSERDIR = ".kchmviewer";


KCHMConfig::KCHMConfig()
{
	QDir dir;
	m_datapath = QDir::homePath () + "/" + APP_PATHINUSERDIR;
	 
	dir.setPath (m_datapath);
	
	if ( !dir.exists() && !dir.mkdir(m_datapath) )
		qWarning( "Could not create directory %s", qPrintable( m_datapath ));

	m_LoadLatestFileOnStartup = false;
	m_onNewChmClick = ACTION_ASK_USER;
	m_onExternalLinkClick = ACTION_ASK_USER;
	m_numOfRecentFiles = 10;
	m_HistoryStoreExtra = true;
	
	// Webkit only present in 4.4+
#if defined (QT_WEBKIT_LIB)
	m_usedBrowser = BROWSER_QTWEBKIT;
#else
	m_usedBrowser = BROWSER_QTEXTBROWSER;
#endif
		
	m_kdeEnableJS = false;
	m_kdeEnableJava = false;
	m_kdeEnablePlugins = true;
	m_kdeEnableRefresh = false;
	
	m_advUseInternalEditor = true;
	m_advLayoutDirectionRL = false;
	m_advAutodetectEncoding = false;
	m_advExternalEditorPath = "/usr/bin/kate";
	
	m_lastOpenedDir = "";
}


KCHMConfig::~KCHMConfig()
{
}

bool KCHMConfig::load()
{
	QFile file (m_datapath + "/config");
	if ( !file.open (QIODevice::ReadOnly) )
		return false; // no error message - not actually a problem
	
	QString line;
	char readbuf[4096];
	bool getting_history = false;
	m_recentFiles.clear();
	
	while ( file.readLine( readbuf, sizeof(readbuf) - 1 ) > 0 )
	{
		line = QString::fromUtf8( readbuf ).trimmed();
		
		// skip empty lines and comments
		if ( line.isEmpty() || line[0] == '#' )
			continue;
		
		QRegExp rxsection ("^\\[(\\w+)\\]$"), rxkeypair ("^(\\w+)\\s*=\\s*(.*)$");
		
		if ( rxsection.indexIn( line ) != -1 )
		{
			if ( rxsection.cap (1) == "settings" )
				getting_history = false;
			else if ( rxsection.cap (1) == "history" )
				getting_history = true;
			else
				qWarning ("Unknown configuration section: %s", qPrintable( rxsection.cap(1) ));
			
			continue;
		}
		else if ( !getting_history && rxkeypair.indexIn( line ) != -1 )
		{
			QString key (rxkeypair.cap (1)), value (rxkeypair.cap(2));
			
			if ( key == "LoadLatestFileOnStartup" )
				m_LoadLatestFileOnStartup = value.toInt() ? true : false;
			else if ( key == "onNewChmClick" )
				m_onNewChmClick = (choose_action_t) value.toInt();
			else if ( key == "onExternalLinkClick" )
				m_onExternalLinkClick = (choose_action_t) value.toInt();
			else if ( key == "HistorySize" )
				m_numOfRecentFiles = value.toInt();
			else if ( key == "HistoryStoreExtra" )
				m_HistoryStoreExtra = value.toInt() ? true : false;
			else if ( key == "UsedBrowser" )
				m_usedBrowser = value.toInt();
			else if ( key == "kdeEnableJS" )
				m_kdeEnableJS = value.toInt() ? true : false;
			else if ( key == "kdeEnableJava" )
				m_kdeEnableJava = value.toInt() ? true : false;
			else if ( key == "kdeEnablePlugins" )
				m_kdeEnablePlugins = value.toInt() ? true : false;
			else if ( key == "kdeEnableRefresh" )
				m_kdeEnableRefresh = value.toInt() ? true : false;
			else if ( key == "LastOpenedDir" )
				m_lastOpenedDir = value;
			else if ( key == "advUseInternalEditor" )
				m_advUseInternalEditor = value.toInt() ? true : false;
			else if ( key == "advExternalEditorPath" )
				m_advExternalEditorPath = value;
			else if ( key == "advLayoutDirectionRL" )
				m_advLayoutDirectionRL = value.toInt() ? true : false;
			else if ( key == "advAutoDetectEncoding" )
				m_advAutodetectEncoding = value.toInt() ? true : false;
			else if ( key == "useSearchEngine" || key == "QtBrowserPath" )
				// Do nothing; not used anymore
				;
			else
				qWarning ("Unknown key=value pair: %s", qPrintable( line ));
		}
		else if ( getting_history )
		{
			if ( m_recentFiles.size() < m_numOfRecentFiles )
				addRecentFile( line );
		}
		else
			qWarning ("Unknown line in configuration: %s", qPrintable( line ));
	}

	// Reset webkit browser to qtextbrowser when older version is running
#if !defined (QT_WEBKIT_LIB)
	if ( m_usedBrowser == BROWSER_QTWEBKIT )
		m_usedBrowser = BROWSER_QTEXTBROWSER;
#endif
	
	return true;
}

bool KCHMConfig::save( )
{
	QFile file( m_datapath + "/config" );
	if ( !file.open (QIODevice::WriteOnly) )
	{
		qWarning( "Could not write settings into file %s: %s", 
		          qPrintable( file.fileName() ), 
		          qPrintable(  file.errorString() ) );
		return false;
	}
	
	QTextStream stream( &file );
	stream.setCodec( "UTF-8" );
	stream << "[settings]\n";
	stream << "LoadLatestFileOnStartup=" << m_LoadLatestFileOnStartup << "\n";

	stream << "onNewChmClick=" << m_onNewChmClick << "\n";
	stream << "onExternalLinkClick=" << m_onExternalLinkClick << "\n";
	stream << "HistorySize=" << m_numOfRecentFiles << "\n";
	stream << "HistoryStoreExtra=" << m_HistoryStoreExtra << "\n";
	stream << "UsedBrowser=" << m_usedBrowser << "\n";
	
	stream << "kdeEnableJS=" << m_kdeEnableJS << "\n";
	stream << "kdeEnableJava=" << m_kdeEnableJava << "\n";
	stream << "kdeEnablePlugins=" << m_kdeEnablePlugins << "\n";
	stream << "kdeEnableRefresh=" << m_kdeEnableRefresh << "\n";
	stream << "advUseInternalEditor=" << m_advUseInternalEditor << "\n";
	stream << "advExternalEditorPath=" << m_advExternalEditorPath << "\n";
	stream << "advLayoutDirectionRL=" << m_advLayoutDirectionRL << "\n";
	stream << "advAutoDetectEncoding=" << m_advAutodetectEncoding << "\n";
	
	stream << "LastOpenedDir=" << m_lastOpenedDir << "\n";	
	
	stream << "\n[history]\n";
	
	// Do not write all the history, but only the needed amount
	for ( int i = 0; i < m_recentFiles.size(); i++ )
		stream << m_recentFiles[m_recentFiles.size() - 1 - i] << "\n";
	
	return true;
}

void KCHMConfig::addRecentFile( const QString & filename )
{
	m_recentFiles.removeAll( filename );
	m_recentFiles.prepend( filename );
	
	while( m_recentFiles.size() > m_numOfRecentFiles )
	{
		// Remove the appropriate history file
		mainWindow->currentSettings()->removeSettings( m_recentFiles.last() );
		m_recentFiles.removeLast();
	}
}
