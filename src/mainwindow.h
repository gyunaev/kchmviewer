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

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "libchmfile.h"

#include "kde-qt.h"
#include "viewwindow.h"
#include "checknewversion.h"

#include "ui_mainwindow.h"


//! Those events could be sent to main window to do useful things. See handleUserEvents()
class UserEvent : public QEvent
{
	public:
		UserEvent( const QString& action, const QStringList& args = QStringList() )
			: QEvent( QEvent::User ), m_action(action), m_args(args)
		{
		}
	
		QString			m_action;
		QStringList		m_args;
};


class RecentFiles;
class NavigationPanel;

class MainWindow : public QMainWindow, public Ui::MainWindow
{
	Q_OBJECT
	
	public:
		// "Open page" parameter flags
		enum
		{
			OPF_CONTENT_TREE = 1 << 0,	//! Locate this page in the content tree
			OPF_ADD2HISTORY	= 1 << 1,	//! Add the previous page into the history
			OPF_NEW_TAB = 1 << 2,		//! Open the page in a new tab
			OPF_BACKGROUND 	= 1 << 3	//! Open the page in a new tab in background
		};
		
	public:
		MainWindow();
		~MainWindow();
	
		bool		openPage ( const QString &url, unsigned int flags = OPF_CONTENT_TREE );
		
		LCHMFile *	chmFile() const	{ return m_chmFile; }
		const QString&	getOpenedFileName () { return m_chmFilename; }
		const QString&	getOpenedFileBaseName () { return m_chmFileBasename; }
		
		ViewWindow * currentBrowser() const;
		Settings   * currentSettings() const { return m_currentSettings; }
		ViewWindowMgr*	viewWindowMgr() const { return m_viewWindowMgr; }
		NavigationPanel * navigator() const { return m_navPanel; }

		void		showInStatusBar (const QString& text);
		void		setTextEncoding (const LCHMTextEncoding * enc);
		QMenu * 	tabItemsContextMenu();
	
		// Called from WindowMgr when another browser tab is activated
		void		browserChanged( ViewWindow * newbrowser );
	
		// Adds some main window actions to the provided popup menu
		void		setupPopupMenu( QMenu * menu );	
	
		// Returns true if currently opened file has TOC/index
		bool		hasTableOfContents() const;
		bool		hasIndex() const;

	public slots:
		// Navigation toolbar icons
		void		navSetBackEnabled( bool enabled );
		void		navSetForwardEnabled( bool enabled );
		
		void 		onOpenPageInNewTab();
		void 		onOpenPageInNewBackgroundTab();
					
		// Actions
		void		actionOpenFile();
		void		actionPrint();
		void		actionEditCopy();
		void		actionEditSelectAll();
		void		actionFindInPage();
		void		actionExtractCHM();
		void		actionChangeSettings();
		void		actionFontSizeIncrease();
		void		actionFontSizeDecrease();
		void		actionViewHTMLsource();
		void		actionToggleFullScreen();
		void		actionShowHideNavigator(bool);
		void		navigatorVisibilityChanged( bool visible );
		void		actionLocateInContentsTab();

		void		actionNavigateBack();
		void		actionNavigateForward();
		void		actionNavigateHome();
		
		void		actionAboutApp();
		void		actionAboutQt();
		
		void		actionSwitchToContentTab();
		void		actionSwitchToIndexTab();
		void		actionSwitchToSearchTab();
		void		actionSwitchToBookmarkTab();
		
		void		actionOpenRecentFile( const QString& file );
		void		actionEncodingChanged( QAction * action );
	
		// Link activation. MainWindow decides whether we should follow this link or not
		// by setting up follow_link appropriately.
		void 		activateLink( const QString & link, bool& follow_link );

		void		updateToolbars();
		void		updateActions();

		void		checkNewVersionAvailable();

	protected slots:
		// Called from the timer in main constructor
		void 		firstShow();

		// checknewversion
		void		newVerAvailError( int  );
		void		newVerAvailable( NewVersionMetaMap metadata );
		
	protected:
		// Reimplemented functions
		void		closeEvent ( QCloseEvent * e );
		bool		event ( QEvent * e );
		
	private:
		bool		parseCmdLineArgs();
		void 		setupActions();
		void		setupLangEncodingMenu();
		
		bool		loadFile( const QString &fileName,  bool call_open_page = true );
		void		closeFile();	
		void		refreshCurrentBrowser();
		
		bool		handleUserEvent( const UserEvent * event );
		
	private:		
		QString 				m_chmFilename;
		QString 				m_chmFileBasename;
		
		Settings			*	m_currentSettings;
		LCHMFile			*	m_chmFile;
		
		QList<QTemporaryFile*>	m_tempFileKeeper;

		QActionGroup		*	m_encodingActions;
		QMenu				*	m_contextMenu;

		RecentFiles			*	m_recentFiles;

		ViewWindowMgr		*	m_viewWindowMgr;
		NavigationPanel		*	m_navPanel;

	private:
		// This is used for application automatic testing
		enum	auto_test_state_t
		{
			STATE_OFF,
			STATE_INITIAL,
			STATE_OPEN_INDEX,
			STATE_SHUTDOWN
		};
		
		auto_test_state_t			m_autoteststate;
	
	private slots:
		void	runAutoTest();
		
};

extern MainWindow * mainWindow;

#endif // MAINWINDOW_H
