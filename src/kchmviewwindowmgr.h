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

#ifndef INCLUDE_KCHMVIEWWINDOWMGR_H
#define INCLUDE_KCHMVIEWWINDOWMGR_H

#include "kde-qt.h"
#include "forwarddeclarations.h"
#include "kchmsettings.h"


class KCHMViewWindowMgr : public QTabWidget
{
	Q_OBJECT
	public:
		KCHMViewWindowMgr( QWidget *parent, QMenu * menuWindow, QAction * actionCloseWindow );
		~KCHMViewWindowMgr( );
		
		// Returns a handle to a currently viewed window.
		// Guaranteeed to return a valid handle, or aborts.
		KCHMViewWindow	* 	current();
		
		// Adds a new tab, creating a new browser window
		KCHMViewWindow	*	addNewTab( bool set_active );
		
		// Sets the tab name and updates Windows menu
		void	setTabName( KCHMViewWindow* window );
		
		void 	invalidate();
		
		// Creates a Window menu
		void 	createMenu( KCHMMainWindow * parent );
		
		// Saves and restores current settings between sessions
		void	restoreSettings( const KCHMSettings::viewindow_saved_settings_t& settings );
		void	saveSettings( KCHMSettings::viewindow_saved_settings_t& settings );
		
	public slots:
		void	closeCurrentWindow();
		
	protected slots:
		void	openNewTab();
		void	onTabChanged( QWidget * newtab );
		void	onCloseWindow( int id );
		void	onActiveWindow( int id );
		void	updateCloseButtons();
		
	private:
		typedef struct
		{
			QWidget			*	widget;
			KCHMViewWindow	*	window;
			int					menuitem;
		} tab_window_t;
		
		void	closeWindow( const tab_window_t& tab );
		void	closeAllWindows();
		void    updateTabAccel();
		QKeySequence key(int);
		
		QMap<QWidget*,tab_window_t>	m_Windows;
		typedef QMap<QWidget*,tab_window_t>::iterator WindowsIterator;
		
        QList<int>     					m_idSlot;
        typedef QList<int>::iterator	IdIterator;
		
		QToolButton			*	m_closeButton;
		QMenu 				*	m_menuWindow;
		QAction				*	m_actionCloseWindow;
};

#endif /* INCLUDE_KCHMVIEWWINDOWMGR_H */
