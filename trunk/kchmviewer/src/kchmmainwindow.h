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

#ifndef KCHMMAINWINDOW_H
#define KCHMMAINWINDOW_H

//FIXME: move Qt includes to kde-qt
#include <QCloseEvent>
#include <QShowEvent>
#include <QEvent>
#include <QMainWindow>

#include "libchmfile.h"

#include "kde-qt.h"
#include "forwarddeclarations.h"
#include "kchmviewwindow.h"
#include "kqtempfile.h"

#include "ui_window_main.h"

//#define ENABLE_AUTOTEST_SUPPORT

//! OpenPage extra flags, specifying extra behavior

//! Locate this page in the content tree, and move the cursor there
static const unsigned int OPF_CONTENT_TREE	= 1 << 0;
//! Add the previous page into the history
static const unsigned int OPF_ADD2HISTORY	= 1 << 1;
//! Open the page in a new tab
static const unsigned int OPF_NEW_TAB 		= 1 << 2;
//! Open the page in a new tab in background
static const unsigned int OPF_BACKGROUND 	= 1 << 3;

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
		KCHMMainWindow();
		~KCHMMainWindow();
	
		bool		openPage ( const QString &url, unsigned int flags = OPF_CONTENT_TREE );
		
		LCHMFile *	chmFile() const	{ return m_chmFile; }
		const QString&	getOpenedFileName () { return m_chmFilename; }
		
		KCHMViewWindow * currentBrowser() const;
		KCHMContentsWindow  * contentsWindow() const { return m_contentsTab; }
		KCHMSettings   * currentSettings() const { return m_currentSettings; }
		KCHMViewWindowMgr*	viewWindowMgr() const { return m_viewWindowMgr; }
		KCHMSearchWindow * searchWindow() const { return m_searchTab; }
		
		void		showInStatusBar (const QString& text);
		void		setTextEncoding (const LCHMTextEncoding * enc);
	
	public slots:
		// Navigation toolbar icons
		void		navSetBackEnabled( bool enabled );
		void		navSetForwardEnabled( bool enabled );
		
		void 		slotOpenPageInNewTab();
		void 		slotOpenPageInNewBackgroundTab();
		void		slotBrowserChanged( KCHMViewWindow * newbrowser );
					
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
		
		// Link activation. MainWindow decides whether we should follow this link or not
		// by setting up follow_link appropriately.
		void 		activateLink ( const QString & link, bool& follow_link );
	
	private slots:
		void slotHistoryMenuItemActivated ( int );
		/*
	
		void slotChangeSettingsMenuItemActivated();
		
		
		void slotToggleFullScreenMode( );
		
		*/
		
	protected:
		// Reimplemented functions
		void 		showEvent( QShowEvent * );
		void		closeEvent ( QCloseEvent * e );
		bool		event ( QEvent * e );
		
	private:
		bool		parseCmdLineArgs();
		void		setupSignals ();
		void 		setupActions();
		
		bool		loadChmFile ( const QString &fileName,  bool call_open_page = true );
		void		closeChmFile();	
		void		refreshCurrentBrowser();
		void		updateHistoryMenu();
		
		void		showOrHideContextWindow( int tabindex );
		void		showOrHideIndexWindow( int tabindex );
		void		showOrHideSearchWindow( int tabindex );
		
		bool		handleUserEvent( const KCHMUserEvent * event );
		void		locateInContentTree( const QString& url );
		
	private:		
		QString 				m_chmFilename;
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
		bool					m_FirstTimeShow;
		
		QMenu				*	m_recentFiles;
		int						m_tabContextPage;	
		int						m_tabIndexPage;
		int						m_tabSearchPage;
		int						m_tabBookmarkPage;
	
		KQTempFileKeeper		m_tempFileKeeper;
				
#if defined (ENABLE_AUTOTEST_SUPPORT)
		enum	auto_test_state_t
		{
			STATE_OFF,
			STATE_INITIAL,
			STATE_CONTENTS_OPENNEXTPAGE,
			STATE_OPEN_INDEX,
			STATE_SHUTDOWN
		};
		
		bool						m_useShortAutotest;
		auto_test_state_t			m_autoteststate;
		QTreeWidgetItemIterator	*	m_autotestlistiterator;
	
	private slots:
		void	runAutoTest();
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
		
};

extern KCHMMainWindow * mainWindow;

#endif // KCHMMAINWINDOW_H
