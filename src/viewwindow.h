/**************************************************************************
 *  Kchmviewer - a portable CHM file viewer with the best support for     *
 *  the international languages                                           *
 *                                                                        *
 *  Copyright (C) 2004-2012 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  Please read http://www.kchmviewer.net/reportbugs.html if you want     *
 *  to report a bug. It lists things I need to fix it!                    *
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

#ifndef VIEWWINDOW_H
#define VIEWWINDOW_H

#include <QWebView>

#include "kde-qt.h"

class ViewWindow : public QWebView
{
	Q_OBJECT

	public:
		enum
		{
			SEARCH_CASESENSITIVE = 0x10,
			SEARCH_BACKWARD = 0x20
		};
	
		ViewWindow( QWidget * parent );
		virtual ~ViewWindow();
	
		//! Open a page from current chm archive
		bool	openUrl (const QUrl& url );
		
		QUrl	getBaseUrl() const	{ return m_base_url; }
		QUrl	getOpenedPage() const	{ return m_openedPage; }
		QUrl	getNewTabLink() const	{ return m_newTabLinkKeeper; }
//		QUrl	makeURLabsolute ( const QUrl&url, bool set_as_base = true );
		
	public: 
		//static QString decodeUrl( const QString &input );

		//! Invalidate current view, doing all the cleanups etc.
		void	invalidate();
	
		//! Popups the print dialog, and prints the current page on the printer.
		bool	printCurrentPage();
	
		//! Search function. find() starts new search, onFindNext and onFindPrevious continue it
		bool	findTextInPage( const QString& text, int flags );
	
		//! Return current ZoomFactor.
		qreal	getZoomFactor() const;
		
		//! Sets ZoomFactor. The value returned by getZoomFactor(), given to this function, should give the same result.
		void	setZoomFactor( qreal zoom );
		
		/*!
		* Return current scrollbar position in view window. Saved on program exit. 
		* There is no restriction on returned value, except that giving this value to 
		* setScrollbarPosition() should move the scrollbar in the same position.
		*/
		int		getScrollbarPosition();
		
		//! Sets the scrollbar position.
		void	setScrollbarPosition(int pos);
	
		//! Select the content of the whole page
		void	clipSelectAll();
	
		//! Copies the selected content to the clipboard
		void	clipCopy();
	
		//! Updates the history toolbar icon status
		void	updateHistoryIcons();

		//! Returns the window title
		QString	getTitle() const;
		
		//! Navigation stuff
		void	navigateBack();
		void	navigateHome();
		void	navigateForward();
		
		//! Keeps the tab URL between link following
		void	setTabKeeper ( const QUrl& link );

	public slots:
		void	zoomIncrease();
		void	zoomDecrease();
		
	protected:
		bool			openPage ( const QUrl& url );
		void			handleStartPageAsImage( QUrl& link );
		
		QMenu * 		getContextMenu( const QUrl& link, QWidget * parent );
		QMenu * 		createStandardContextMenu( QWidget * parent );
		
		// Overriden to change the source
		void			setSource ( const QUrl & name );
		QString			anchorAt( const QPoint & pos );

		// Overloaded to provide custom context menu
		void 			contextMenuEvent( QContextMenuEvent *e );
		void			mouseReleaseEvent ( QMouseEvent * event );

	private slots:
		void	onLoadFinished ( bool ok );

	private:
		//FIXME: embedded search
		QMenu 				*	m_contextMenu;
		QMenu 				*	m_contextMenuLink;

		QUrl					m_openedPage;
		QUrl					m_lastOpenedPage;
		QUrl					m_base_url;
	
		// This member keeps a "open new tab" link between getContextMenu()
		// call and appropriate slot call
		QUrl					m_newTabLinkKeeper;

		// Keeps the scrollbar position to move after the page is loaded
		int						m_storedScrollbarPosition;
};

#endif
