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

#include "kde-qt.h"

#include "libchmfile.h"

#include "forwarddeclarations.h"
#include "kchmviewwindow.h"


#define ENABLE_AUTOTEST_SUPPORT

//! OpenPage extra flags, specifying extra behavior

//! Locate this page in the content tree, and move the cursor there
static const unsigned int OPF_CONTENT_TREE	= 1 << 0;
//! Add the previous page into the history
static const unsigned int OPF_ADD2HISTORY	= 1 << 1;
//! Open the page in a new tab
static const unsigned int OPF_NEW_TAB 		= 1 << 2;
//! Open the page in a new tab in background
static const unsigned int OPF_BACKGROUND 	= 1 << 3;


class KCHMMainWindow : public KQMainWindow
{
		Q_OBJECT
	
	public:
		KCHMMainWindow();
		~KCHMMainWindow();
	
		bool		openPage ( const QString &url, unsigned int flags = OPF_CONTENT_TREE );
		
		LCHMFile *	chmFile() const	{ return m_chmFile; }
		const QString&	getOpenedFileName () { return m_chmFilename; }
		
		KCHMViewWindow * currentBrowser() const;
		KCHMContentsWindow  * contentsWindow() const { return m_contentsWindow; }
		KCHMSettings   * currentSettings() const { return m_currentSettings; }
		KCHMViewWindowMgr*	viewWindowMgr() const { return m_viewWindowMgr; }
		KCHMNavToolbar * navigationToolbar() const { return m_navToolbar; };
		
		void		showInStatusBar (const QString& text)	{ statusBar()->message( text, 2000 ); }
		void		setTextEncoding (const LCHMTextEncoding * enc);
			
	public slots:
		void slotOnTreeClicked( QListViewItem *item );
		void slotOnTreeDoubleClicked( QListViewItem *item, const QPoint &, int );
		
		void slotAddBookmark ( );
		void slotOpenPageInNewTab( );
		void slotOpenPageInNewBackgroundTab( );
		void slotEnableFullScreenMode( bool enable );
		void slotShowContentsWindow( bool show );
		void slotLocateInContentWindow( );
		void slotBrowserChanged( KCHMViewWindow * newbrowser );
					
	private slots:
		void slotLinkClicked ( const QString & link, bool& follow_link );
				
		void slotOpenMenuItemActivated();
		void slotPrintMenuItemActivated();
	
		void slotAboutMenuItemActivated();
		void slotAboutQtMenuItemActivated();
	
		void slotActivateContentTab();
		void slotActivateIndexTab();
		void slotActivateSearchTab();
		void slotActivateBookmarkTab();
		
		void slotBrowserSelectAll();
		void slotBrowserCopy();
		void slotExtractCHM();
	
		void slotChangeSettingsMenuItemActivated();
		void slotHistoryMenuItemActivated ( int );
		
		void slotToggleFullScreenMode( );
		
		void slotNavigateBack()	{	currentBrowser()->navigateBack(); }
		void slotNavigateHome()	{	currentBrowser()->navigateHome(); }
		void slotNavigateForward(){	currentBrowser()->navigateForward(); }
		
	private:
		bool	parseCmdLineArgs();
		void 	showEvent( QShowEvent * );
		void	closeEvent ( QCloseEvent * e );
		void	setupSignals ();
	
		void 	setupToolbarsAndMenu ( );
		bool	loadChmFile ( const QString &fileName,  bool call_open_page = true );
		void	closeChmFile();	
		void	refreshCurrentBrowser();
		void	updateHistoryMenu();
		
		void	showOrHideContextWindow( int tabindex );
		void	showOrHideIndexWindow( int tabindex );
		void	showOrHideSearchWindow( int tabindex );
		
		void	locateInContentTree( const QString& url );
		
		QString 				m_chmFilename;
		QString					m_aboutDlgMenuText;	// to show in KDE or Qt about dialogs
		
		KCHMViewWindowMgr	*	m_viewWindowMgr;
		KCHMIndexWindow		*	m_indexWindow;
		KCHMSearchWindow	*	m_searchWindow;
		KCHMBookmarkWindow	*	m_bookmarkWindow;
		KCHMContentsWindow	*	m_contentsWindow;
	
		KQTabWidget			*	m_tabWidget;
		QSplitter 			*	m_windowSplitter;
	
		KCHMSearchAndViewToolbar	*	m_searchToolbar;
		KCHMNavToolbar		*	m_navToolbar;
		
		KCHMSettings		*	m_currentSettings;
		
		LCHMFile			*	m_chmFile;
		bool					m_FirstTimeShow;
		
		KQPopupMenu			*	m_menuHistory;
		
		int						m_tabContextPage;	
		int						m_tabIndexPage;
		int						m_tabSearchPage;
		int						m_tabBookmarkPage;
	
#if defined (ENABLE_AUTOTEST_SUPPORT)
		enum	auto_test_state_t
		{
			STATE_OFF,
			STATE_INITIAL,
			STATE_CONTENTS_OPENNEXTPAGE,
			STATE_OPEN_INDEX,
			STATE_SHUTDOWN
		};
		
		bool					m_useShortAutotest;
		auto_test_state_t		m_autoteststate;
		QListViewItemIterator	m_autotestlistiterator;
	
	private slots:
		void	runAutoTest();
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
		
};

extern KCHMMainWindow * mainWindow;

#endif // KCHMMAINWINDOW_H
