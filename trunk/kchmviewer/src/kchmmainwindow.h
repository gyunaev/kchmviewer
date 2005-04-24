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
	
	KCHMViewWindow * getViewWindow() { return viewWindow; }

	void		showInStatusBar (const QString& text)	{ statusBar()->message( text, 2000 ); }
	void		setTextEncoding (const KCHMTextEncoding::text_encoding_t * enc);
	
public slots:
	void 	onTreeClicked( QListViewItem *item );
	void	addBookmark ( );
			
private slots:
	void onLinkClicked ( const QString & link );
	void onBackwardAvailable ( bool enabled );
	void onForwardAvailable ( bool enabled );

    void choose();
    void print();
    void backward();
    void forward();
    void gohome();

    void about();
    void aboutQt();

private:
	bool	parseCmdLineArgs();
	void 	showEvent( QShowEvent * );
	void	closeEvent ( QCloseEvent * e );

	void 	setupToolbarsAndMenu ( );
	void	loadChmFile ( const QString &fileName );
	void	CloseChmFile();	
	void	updateView();
	
    QString 				filename;
	
	KCHMViewWindow		*	viewWindow;
	KCHMIndexWindow		*	indexWindow;
	KCHMSearchWindow	*	searchWindow;
	KCHMBookmarkWindow	*	bookmarkWindow;

	KQListView			*	contentsWindow;	
	QTabWidget			*	m_tabWidget;
	QToolButton			*	m_toolbarIconBackward;
	QToolButton			*	m_toolbarIconForward;
	
	KCHMSearchAndViewToolbar	*	m_searchToolbar;
	
	KCHMSettings		*	m_currentSettings;
	
	CHMFile				*	chmfile;
	bool					m_FirstTimeShow;

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
