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

#ifndef KCHMMAINWINDOW_H
#define KCHMMAINWINDOW_H

#include "libchmfile.h"

#include "kde-qt.h"
#include "kchmviewwindow.h"

#include "ui_window_main.h"

#define ENABLE_AUTOTEST_SUPPORT

//! OpenPage extra flags, specifying extra behavior


//! Those events could be sent to main window to do useful things. See handleUserEvents()
class KCHMUserEvent : public QEvent
{
	public:
		KCHMUserEvent( const QString& action, const QStringList& args = QStringList()) 
			: QEvent( QEvent::User ), m_action(action), m_args(args) {};
	
		QString			m_action;
		QStringList		m_args;
};



class KCHMMainWindow : public QMainWindow, public Ui::MainWindow
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
		KCHMMainWindow();
		~KCHMMainWindow();
	
		bool		openPage ( const QString &url, unsigned int flags = OPF_CONTENT_TREE );
		
		LCHMFile *	chmFile() const	{ return m_chmFile; }
		const QString&	getOpenedFileName () { return m_chmFilename; }
		const QString&	getOpenedFileBaseName () { return m_chmFileBasename; }
		
		KCHMViewWindow * currentBrowser() const;
		KCHMContentsWindow  * contentsWindow() const { return m_contentsTab; }
		KCHMSettings   * currentSettings() const { return m_currentSettings; }
		KCHMViewWindowMgr*	viewWindowMgr() const { return m_viewWindowMgr; }
		KCHMSearchWindow * searchWindow() const { return m_searchTab; }
		
		void		showInStatusBar (const QString& text);
		void		setTextEncoding (const LCHMTextEncoding * enc);
		QMenu * 	tabItemsContextMenu();
	
		// Called from WindowMgr when another browser tab is activated
		void		browserChanged( KCHMViewWindow * newbrowser );
	
		// Adds some main window actions to the provided popup menu
		void		setupPopupMenu( QMenu * menu );	
	
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
		void		actionAddBookmark();		
		void		actionFontSizeIncrease();
		void		actionFontSizeDecrease();
		void		actionViewHTMLsource();
		void		actionToggleFullScreen();
		void		actionToggleContentsTab();
		void		actionLocateInContentsTab();

		void		actionNavigateBack();
		void		actionNavigateForward();
		void		actionNavigateHome();
		void		actionNavigatePrevInToc();
		void		actionNavigateNextInToc();
		
		void		actionAboutApp();
		void		actionAboutQt();
		
		void		actionSwitchToContentTab();
		void		actionSwitchToIndexTab();
		void		actionSwitchToSearchTab();
		void		actionSwitchToBookmarkTab();
		
		void		actionOpenRecentFile();
		void		actionEncodingChanged( QAction * action );
	
		// Link activation. MainWindow decides whether we should follow this link or not
		// by setting up follow_link appropriately.
		void 		activateLink( const QString & link, bool& follow_link );

	protected slots:
		// Called from the timer in main constructor
		void 		firstShow();
		
	protected:
		// Reimplemented functions
		void		closeEvent ( QCloseEvent * e );
		bool		event ( QEvent * e );
		
	private:
		bool		parseCmdLineArgs();
		void		setupSignals ();
		void 		setupActions();
		void		setupLangEncodingMenu();
		
		bool		loadFile( const QString &fileName,  bool call_open_page = true );
		void		closeFile();	
		void		refreshCurrentBrowser();
		
		void		showOrHideContextWindow( int tabindex );
		void		showOrHideIndexWindow( int tabindex );
		void		showOrHideSearchWindow( int tabindex );
		
		// Creates and initializes the recent files array, and adds the 
		// entries logic to the menu
		void		recentFilesInit( QMenu * menu );
		void		recentFilesUpdate();
	
		bool		handleUserEvent( const KCHMUserEvent * event );
		void		locateInContentTree( const QString& url );
		
	private:		
		QString 				m_chmFilename;
		QString 				m_chmFileBasename;
		QString					m_aboutDlgMenuText;	// to show in KDE or Qt about dialogs
		
		KCHMViewWindowMgr	*	m_viewWindowMgr;
		KCHMIndexWindow		*	m_indexTab;
		KCHMSearchWindow	*	m_searchTab;
		KCHMBookmarkWindow	*	m_bookmarkWindow;
		KCHMContentsWindow	*	m_contentsTab;
	
		KQTabWidget			*	m_tabWidget;
		QSplitter 			*	m_windowSplitter;
	
		KCHMSettings		*	m_currentSettings;
		LCHMFile			*	m_chmFile;
		
		int						m_tabContextPage;	
		int						m_tabIndexPage;
		int						m_tabSearchPage;
		int						m_tabBookmarkPage;
	
		QList<QTemporaryFile*>	m_tempFileKeeper;

		int						m_numOfRecentFiles;
		QVector<QAction*>		m_recentFiles;
		QAction 			*	m_recentFileSeparator;
	
		QActionGroup		*	m_encodingActions;
		QMenu				*	m_contextMenu;
	
#if defined (ENABLE_AUTOTEST_SUPPORT)
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
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
		
};

extern KCHMMainWindow * mainWindow;

#endif // KCHMMAINWINDOW_H
