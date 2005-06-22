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

#ifndef KCHMMAINWINDOW_H
#define KCHMMAINWINDOW_H

#include "kde-qt.h"

#include "forwarddeclarations.h"
#include "kchmtextencoding.h"


#define ENABLE_AUTOTEST_SUPPORT

class KCHMMainWindow : public KQMainWindow
{
    Q_OBJECT

public:
    KCHMMainWindow();
    ~KCHMMainWindow();

	bool		openPage ( const QString &url, bool set_in_tree = true );
	
	CHMFile *	getChmFile() const	{ return chmfile; }
	const QString&	getOpenedFileName () { return m_chmFilename; }
	
	KCHMViewWindow * getViewWindow() { return viewWindow; }
	KCHMSettings   * getCurrentSettings() const { return m_currentSettings; }

	void		showInStatusBar (const QString& text)	{ statusBar()->message( text, 2000 ); }
	void		setTextEncoding (const KCHMTextEncoding::text_encoding_t * enc);
	
public slots:
	void 	onTreeClicked( QListViewItem *item );
	void	addBookmark ( );
			
private slots:
	void slotLinkClicked ( const QString & link, bool& follow_link );
	void slotHistoryAvailabilityChanged (bool enable_backward, bool enable_forward);

    void slotOpenMenuItemActivated();
	void slotPrintMenuItemActivated();
	void slotBackwardMenuItemActivated();
	void slotForwardMenuItemActivated();
	void slotHomeMenuItemActivated();

	void slotAboutMenuItemActivated();
	void slotAboutQtMenuItemActivated();

	void slotActivateContentTab();
	void slotActivateIndexTab();
	void slotActivateSearchTab();
	void slotActivateBookmarkTab();
	
	void slotBrowserSelectAll();
	void slotBrowserCopy();

	void slotChangeSettingsMenuItemActivated();
	void slotHistoryMenuItemActivated ( int );
	
private:
	bool	parseCmdLineArgs();
	void 	showEvent( QShowEvent * );
	void	closeEvent ( QCloseEvent * e );
	void	setupSignals ();
			
	void 	setupToolbarsAndMenu ( );
	bool	loadChmFile ( const QString &fileName,  bool call_open_page = true );
	void	closeChmFile();	
	void	updateView();
	void	updateHistoryMenu();
	void	createViewWindow();
	
    QString 				m_chmFilename;
	
	KCHMViewWindow		*	viewWindow;
	KCHMIndexWindow		*	indexWindow;
	KCHMSearchWindow	*	searchWindow;
	KCHMBookmarkWindow	*	bookmarkWindow;

	KQListView			*	contentsWindow;	
	KQTabWidget			*	m_tabWidget;
	QToolButton			*	m_toolbarIconBackward;
	QToolButton			*	m_toolbarIconForward;
	QSplitter 			*	m_windowSplitter;

	KCHMSearchAndViewToolbar	*	m_searchToolbar;
	
	KCHMSettings		*	m_currentSettings;
	
	CHMFile				*	chmfile;
	bool					m_FirstTimeShow;
	
	KQPopupMenu			*	m_menuHistory;
	
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
	
	auto_test_state_t		m_autoteststate;
	QListViewItemIterator	m_autotestlistiterator;

private slots:
	void	runAutoTest();
#endif /* defined (ENABLE_AUTOTEST_SUPPORT) */
};

extern KCHMMainWindow * mainWindow;

#endif // KCHMMAINWINDOW_H
