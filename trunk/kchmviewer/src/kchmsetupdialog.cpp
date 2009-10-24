/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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

#include "kde-qt.h"
#include "kchmconfig.h"
#include "kchmsetupdialog.h"
#include "version.h"


KCHMSetupDialog::KCHMSetupDialog(QWidget *parent)
	: QDialog(parent), Ui::DialogSetup()
{
	setupUi( this );
	
	connect( btnBrowse, SIGNAL( clicked() ), this, SLOT( browseExternalEditor() ) );
	
	// Set up the parameters
	m_radioOnBeginOpenDialog->setChecked ( !appConfig.m_LoadLatestFileOnStartup );
	m_radioOnBeginOpenLast->setChecked ( appConfig.m_LoadLatestFileOnStartup );
	m_historySize->setValue ( appConfig.m_numOfRecentFiles );
	m_rememberHistoryInfo->setChecked ( appConfig.m_HistoryStoreExtra );
	
	m_radioExtLinkOpenAlways->setChecked ( appConfig.m_onExternalLinkClick == KCHMConfig::ACTION_ALWAYS_OPEN );
	m_radioExtLinkAsk->setChecked ( appConfig.m_onExternalLinkClick == KCHMConfig::ACTION_ASK_USER );
	m_radioExtLinkOpenNever->setChecked ( appConfig.m_onExternalLinkClick == KCHMConfig::ACTION_DONT_OPEN );
	
	m_radioNewChmOpenAlways->setChecked ( appConfig.m_onNewChmClick == KCHMConfig::ACTION_ALWAYS_OPEN );
	m_radioNewChmAsk->setChecked ( appConfig.m_onNewChmClick == KCHMConfig::ACTION_ASK_USER );
	m_radioNewChmOpenNever->setChecked ( appConfig.m_onNewChmClick == KCHMConfig::ACTION_DONT_OPEN );

#if !defined (USE_KDE)
	m_radioUseKHTMLPart->setEnabled ( false );
#endif

#if !defined (QT_WEBKIT_LIB)
	m_radioUseQtWebkit->setEnabled ( false );
#endif

	switch ( appConfig.m_usedBrowser )
	{
		default:
			m_radioUseQtextBrowser->setChecked ( true );
			break;

#if defined (USE_KDE)			
		case KCHMConfig::BROWSER_KHTMLPART:
			m_radioUseKHTMLPart->setChecked( true );
			break;
#endif			
			
#if defined (QT_WEBKIT_LIB)
		case KCHMConfig::BROWSER_QTWEBKIT:
			m_radioUseQtWebkit->setChecked( true );
			break;
#endif			
	}
	
	m_enableJS->setChecked ( appConfig.m_kdeEnableJS );
	m_enablePlugins->setChecked ( appConfig.m_kdeEnablePlugins );
	m_enableJava->setChecked ( appConfig.m_kdeEnableJava );
	m_enableRefresh->setChecked ( appConfig.m_kdeEnableRefresh );
	
	m_advExternalProgramName->setText( appConfig.m_advExternalEditorPath );
	m_advViewSourceExternal->setChecked ( !appConfig.m_advUseInternalEditor );
	m_advViewSourceInternal->setChecked ( appConfig.m_advUseInternalEditor );
	
	m_numOfRecentFiles = appConfig.m_numOfRecentFiles;

	boxAutodetectEncoding->setChecked( appConfig.m_advAutodetectEncoding );
	boxLayoutDirectionRL->setChecked( appConfig.m_advLayoutDirectionRL );
}

KCHMSetupDialog::~KCHMSetupDialog()
{
}


void KCHMSetupDialog::accept()
{
	appConfig.m_LoadLatestFileOnStartup = m_radioOnBeginOpenLast->isChecked();
	appConfig.m_numOfRecentFiles = m_historySize->value();
	appConfig.m_HistoryStoreExtra = m_rememberHistoryInfo->isChecked();

	if ( m_radioExtLinkOpenAlways->isChecked () )
		appConfig.m_onExternalLinkClick = KCHMConfig::ACTION_ALWAYS_OPEN;
	else if ( m_radioExtLinkAsk->isChecked () )
		appConfig.m_onExternalLinkClick = KCHMConfig::ACTION_ASK_USER;
	else
		appConfig.m_onExternalLinkClick = KCHMConfig::ACTION_DONT_OPEN;

	if ( m_radioNewChmOpenAlways->isChecked () )
		appConfig.m_onNewChmClick = KCHMConfig::ACTION_ALWAYS_OPEN;
	else if ( m_radioNewChmAsk->isChecked () )
		appConfig.m_onNewChmClick = KCHMConfig::ACTION_ASK_USER;
	else
		appConfig.m_onNewChmClick = KCHMConfig::ACTION_DONT_OPEN;

		// Check the changes
	bool need_restart = false;
		
	if ( appConfig.m_kdeEnableJS != m_enableJS->isChecked() )
	{
		need_restart = true;
		appConfig.m_kdeEnableJS = m_enableJS->isChecked();
	}
		
	if ( appConfig.m_kdeEnablePlugins != m_enablePlugins->isChecked() )
	{
		need_restart = true;
		appConfig.m_kdeEnablePlugins = m_enablePlugins->isChecked();
	}
		
	if ( appConfig.m_kdeEnableJava != m_enableJava->isChecked() )
	{
		need_restart = true;
		appConfig.m_kdeEnableJava = m_enableJava->isChecked();
	}
		
	if ( appConfig.m_kdeEnableRefresh != m_enableRefresh->isChecked() )
	{
		need_restart = true;
		appConfig.m_kdeEnableRefresh = m_enableRefresh->isChecked();
	}

	int new_browser = KCHMConfig::BROWSER_QTEXTBROWSER;
	
	if ( m_radioUseKHTMLPart->isChecked() )
		new_browser = KCHMConfig::BROWSER_KHTMLPART;
	else if ( m_radioUseQtWebkit->isChecked() )
		new_browser = KCHMConfig::BROWSER_QTWEBKIT;

	if ( new_browser != appConfig.m_usedBrowser )
	{
		need_restart = true;
		appConfig.m_usedBrowser = new_browser;
	}
		
	appConfig.m_advExternalEditorPath = m_advExternalProgramName->text();
	appConfig.m_advUseInternalEditor = m_advViewSourceExternal->isChecked();
	appConfig.m_advUseInternalEditor = m_advViewSourceInternal->isChecked();
		
	if ( appConfig.m_numOfRecentFiles != m_numOfRecentFiles )
		need_restart = true;
	
	// Autodetect encoding
	if ( appConfig.m_advAutodetectEncoding != boxAutodetectEncoding->isChecked() )
		need_restart = true;
	
	appConfig.m_advAutodetectEncoding = boxAutodetectEncoding->isChecked();
			
	// Layout direction management
	bool layout_rl = boxLayoutDirectionRL->isChecked();
	
	if ( layout_rl != appConfig.m_advLayoutDirectionRL )
	{
		appConfig.m_advLayoutDirectionRL = layout_rl;
		need_restart = true;
	}
		
	appConfig.save();
		
	if ( need_restart )
		QMessageBox::information( this,
		 						  APP_NAME,
   								  i18n( "Changing those options requires restarting the application to take effect." )	);

	QDialog::accept();
}


void KCHMSetupDialog::browseExternalEditor()
{
#if defined (USE_KDE)
        QString exec = KFileDialog::getOpenFileName( KUrl(), i18n("*|Executables"), this, i18n("Choose an editor executable"));
#else
	QString exec = QFileDialog::getOpenFileName(this,
								i18n("Choose an editor executable"), 
			   					QString::null, 
	  							i18n( "Executables (*)") );
#endif

	if ( !exec.isEmpty() )
		m_advExternalProgramName->setText( exec );
}
