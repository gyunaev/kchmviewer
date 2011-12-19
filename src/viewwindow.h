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
		bool	openUrl (const QString& url );
		
		QString	getBaseUrl() const	{ return m_base_url; }
		QString	getOpenedPage() const	{ return m_openedPage; }
		QString	getNewTabLink() const	{ return m_newTabLinkKeeper; }
		QString	makeURLabsolute ( const QString &url, bool set_as_base = true );
		
	public: 
		static QString decodeUrl( const QString &input );

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
	
		//! Returns the window title
		QString	getTitle() const;
		
		//! Navigation stuff
		void	navigateBack();
		void	navigateHome();
		void	navigateForward();
		
		//! Navigation auxiliary stuff
		void	setHistoryMaxSize (unsigned int size) { m_historyMaxSize = size; }
		void	addNavigationHistory( const QString & url, int scrollpos );
		void 	updateNavigationToolbar();
		
		//! Keeps the tab URL between link following
		void	setTabKeeper ( const QString& link );

	public slots:
		void	zoomIncrease();
		void	zoomDecrease();
		
	protected:
		bool	openPage ( const QString& url );
		virtual void	handleStartPageAsImage( QString& link );
		
		QMenu * 		getContextMenu( const QString& link, QWidget * parent );
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
		//! History
		class UrlHistory
		{
			public:
				UrlHistory() { scrollbarpos = 0; }
				UrlHistory( const QString& _url, int _scrollbarpos )
					: url(_url), scrollbarpos(_scrollbarpos) {}
			
				const QString&  getUrl() const { return url; }
				int 			getScrollPosition() const { return scrollbarpos; }
				void			setScrollPosition( int pos ) { scrollbarpos = pos; }
				
			private:
				QString  	url;
				int 		scrollbarpos;
		};
	
		int						m_historyMaxSize;
		int						m_historyCurrentPos;
		QMenu 				*	m_contextMenu;
		QMenu 				*	m_contextMenuLink;
		QList<UrlHistory>		m_history;

		QString 				m_openedPage;
		QString 				m_lastOpenedPage;
		QString					m_base_url;
	
		// This member keeps a "open new tab" link between getContextMenu()
		// call and appropriate slot call
		QString					m_newTabLinkKeeper;

		// Keeps the scrollbar position to move after the page is loaded
		int						m_storedScrollbarPosition;
};

#endif
