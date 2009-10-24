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

#ifndef INCLUDE_KCHMVIEWWINDOWMGR_H
#define INCLUDE_KCHMVIEWWINDOWMGR_H

#include "kde-qt.h"
#include "kchmsettings.h"
#include "ui_window_browser.h"


class KCHMViewWindowMgr : public QWidget, public Ui::TabbedBrowser
{
	Q_OBJECT
	public:
		enum SearchResultStatus
		{
			SearchResultFound,
			SearchResultNotFound,
			SearchResultFoundWrapped
		};
	
		KCHMViewWindowMgr( QWidget *parent );
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
		void 	createMenu( KCHMMainWindow * parent, QMenu * menuWindow, QAction * actionCloseWindow );
		
		// Saves and restores current settings between sessions
		void	restoreSettings( const KCHMSettings::viewindow_saved_settings_t& settings );
		void	saveSettings( KCHMSettings::viewindow_saved_settings_t& settings );
		
		void	setCurrentPage( int index );
		int		currentPageIndex() const;
	
	public slots:
		void	onCloseCurrentWindow();
		void	onActivateFind();
		void	onFindNext();
		void	onFindPrevious();
		void	indicateFindResultStatus( SearchResultStatus status );
		
	protected slots:
		void	openNewTab();
		void	onTabChanged( QWidget * newtab );
		void	updateCloseButtons();
		void	activateWindow();
		
		void	editTextEdited( const QString & text );
	
	private:
		void	find();
		
		typedef struct
		{
			QWidget			*	widget;
			KCHMViewWindow	*	window;
			QAction			*	action;
		} TabData;
		
		void	closeAllWindows();
		void	closeWindow( QWidget * widget );		
		TabData * findTab( QWidget * widget );
				
		// Storage of all available windows
		QList< TabData >	m_Windows;
		typedef QList< TabData >::iterator WindowsIterator;
		
		QToolButton			*	m_closeButton;
		QMenu 				*	m_menuWindow;
		QAction				*	m_actionCloseWindow;
	
		// Window menu actions. Contains one action per window. They are not 
		// linked permanently - if a middle window is deleted, all the following
		// actions will be relinked and replaced.
		QList< QAction* >		m_actions;
};

#endif /* INCLUDE_KCHMVIEWWINDOWMGR_H */
