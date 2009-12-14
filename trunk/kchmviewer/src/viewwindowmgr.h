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

#ifndef VIEWWINDOWMGR_H
#define VIEWWINDOWMGR_H

#include "kde-qt.h"
#include "settings.h"
#include "ui_window_browser.h"

// A small overriden class to handle a middle click
// We cannot embed it into .cpp because of O_OBJECT :(
class ViewWindowTabs : public QTabWidget
{
	Q_OBJECT

	public:
		ViewWindowTabs( QWidget * parent );

		virtual ~ViewWindowTabs();

	signals:
		void mouseMiddleClickTab( int tab );

	protected:
		void mouseReleaseEvent ( QMouseEvent * event );
};


class ViewWindowTabs;

class ViewWindowMgr : public QWidget, public Ui::TabbedBrowser
{
	Q_OBJECT
	public:
		enum SearchResultStatus
		{
			SearchResultFound,
			SearchResultNotFound,
			SearchResultFoundWrapped
		};
	
		ViewWindowMgr( QWidget *parent );
		~ViewWindowMgr( );
		
		// Returns a handle to a currently viewed window.
		// Guaranteeed to return a valid handle, or aborts.
		ViewWindow	* 	current();
		
		// Adds a new tab, creating a new browser window
		ViewWindow	*	addNewTab( bool set_active );
		
		// Sets the tab name and updates Windows menu
		void	setTabName( ViewWindow* window );
		
		void 	invalidate();
		
		// Creates a Window menu
		void 	createMenu( MainWindow * parent, QMenu * menuWindow, QAction * actionCloseWindow );
		
		// Saves and restores current settings between sessions
		void	restoreSettings( const Settings::viewindow_saved_settings_t& settings );
		void	saveSettings( Settings::viewindow_saved_settings_t& settings );
		
		void	setCurrentPage( int index );
		int		currentPageIndex() const;
	
	public slots:
		void	onCloseCurrentWindow();
		void	onCloseWindow( int num );
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
			ViewWindow		*	window;
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

		ViewWindowTabs		*	m_tabWidget;
};

#endif /* INCLUDE_KCHMVIEWWINDOWMGR_H */
