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

#include <QTextStream>
#include <QSettings>

#include "kde-qt.h"
#include "config.h"
#include "settings.h"
#include "mainwindow.h"

Config * pConfig;

const char * APP_PATHINUSERDIR = ".kchmviewer";

Config::Config()
{
	QDir dir;
	m_datapath = QDir::homePath () + "/" + APP_PATHINUSERDIR;
	 
	dir.setPath (m_datapath);
	
	if ( !dir.exists() && !dir.mkdir(m_datapath) )
		qWarning( "Could not create directory %s", qPrintable( m_datapath ));

	QSettings settings;
	m_startupMode = (Config::StartupMode) settings.value( "general/onstartup", STARTUP_DO_NOTHING ).toInt();
	m_onNewChmClick = (Config::choose_action_t) settings.value( "general/onnewchm", ACTION_ASK_USER ).toInt();
	m_onExternalLinkClick = (Config::choose_action_t) settings.value( "general/onexternal", ACTION_ASK_USER ).toInt();
	m_numOfRecentFiles = settings.value( "general/maxrecentfiles", 10 ).toInt();
	m_HistoryStoreExtra = settings.value( "general/extrahistory", true ).toBool();
	m_usedBrowser = settings.value( "general/usebrowser", BROWSER_QTEXTBROWSER ).toInt();
	m_kdeEnableJS = settings.value( "browser/enablejs", false ).toBool();
	m_kdeEnableJava = settings.value( "browser/enablejava", false ).toBool();
	m_kdeEnablePlugins = settings.value( "browser/enableplugins", true ).toBool();
	m_kdeEnableRefresh = settings.value( "browser/enablerefresh", false ).toBool();
	m_advUseInternalEditor = settings.value( "advanced/internaleditor", true ).toBool();
	m_advLayoutDirectionRL = settings.value( "advanced/layoutltr", false ).toBool();
	m_advAutodetectEncoding = settings.value( "advanced/autodetectenc", false ).toBool();
	m_advExternalEditorPath = settings.value( "advanced/editorpath", "/usr/bin/kate" ).toString();
	m_advCheckNewVersion = settings.value( "advanced/checknewver", true ).toBool();
	m_toolbarMode = (Config::ToolbarMode) settings.value( "advanced/toolbarmode", TOOLBAR_LARGEICONSTEXT ).toInt();
	m_lastOpenedDir = settings.value( "advanced/lastopendir", "." ).toString();

	// Reset webkit browser to qtextbrowser when older version is running
#if !defined (QT_WEBKIT_LIB)
	if ( m_usedBrowser == BROWSER_QTWEBKIT )
		m_usedBrowser = BROWSER_QTEXTBROWSER;
#endif
}


void Config::save( )
{
	QSettings settings;

	settings.setValue( "general/onstartup", m_startupMode );
	settings.setValue( "general/onnewchm", m_onNewChmClick );
	settings.setValue( "general/onexternal", m_onExternalLinkClick );
	settings.setValue( "general/maxrecentfiles", m_numOfRecentFiles );
	settings.setValue( "general/extrahistory", m_HistoryStoreExtra );
	settings.setValue( "general/usebrowser", m_usedBrowser );
	settings.setValue( "browser/enablejs", m_kdeEnableJS );
	settings.setValue( "browser/enablejava", m_kdeEnableJava );
	settings.setValue( "browser/enableplugins", m_kdeEnablePlugins );
	settings.setValue( "browser/enablerefresh", m_kdeEnableRefresh );
	settings.setValue( "advanced/internaleditor", m_advUseInternalEditor );
	settings.setValue( "advanced/layoutltr", m_advLayoutDirectionRL );
	settings.setValue( "advanced/autodetectenc", m_advAutodetectEncoding );
	settings.setValue( "advanced/editorpath", m_advExternalEditorPath );
	settings.setValue( "advanced/checknewver", m_advCheckNewVersion );
	settings.setValue( "advanced/toolbarmode", m_toolbarMode );
	settings.setValue( "advanced/lastopendir", m_lastOpenedDir );
}
