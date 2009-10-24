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

#ifndef KCHMVIEWWINDOW_QTEXTBROWSER_H
#define KCHMVIEWWINDOW_QTEXTBROWSER_H

#include "kde-qt.h"

#include "kchmviewwindow.h"


class KCHMViewWindow_QTextBrowser : public QTextBrowser, public KCHMViewWindow
{
	Q_OBJECT
	public:
		KCHMViewWindow_QTextBrowser( QTabWidget * parent );
		~KCHMViewWindow_QTextBrowser();

		//! Open a page from current chm archive
		virtual bool	openPage (const QString& url);
		
		//! Invalidate current view, doing all the cleanups etc.
		virtual void	invalidate();
	
		//! Return current ZoomFactor.
		virtual int		getZoomFactor() const { return m_zoomfactor; }
		
		//! Sets ZoomFactor. The value returned by getZoomFactor(), given to this function, should give the same result.
		virtual void	setZoomFactor (int zoom);
		
		//! Relatively changes ZoomFactor. Most common values are -1 and 1.
		virtual void	addZoomFactor (int value);
	
		//! Popups the print dialog, and prints the current page on the printer.
		virtual bool	printCurrentPage();
	
		//! Select the content of the whole page
		virtual void	clipSelectAll();
	
		//! Copies the selected content to the clipboard
		virtual void	clipCopy();
	
		//! Implements "find in page" functionality
		virtual void	find( const QString& text, int flags );
		virtual void	onFindNext();
		virtual void	onFindPrevious();
	
		/*!
		* Return current scrollbar position in view window. Saved on program exit. 
		* There is no restriction on returned value, except that giving this value to 
		* setScrollbarPosition() should move the scrollbar in the same position.
		*/
		virtual int		getScrollbarPosition();
		
		//! Sets the scrollbar position.
		virtual void	setScrollbarPosition(int pos);
	
		virtual QObject *	getQObject() { return this; }
		virtual QWidget *	getQWidget() { return this; }
	
		static	QString decodeUrl( const QString &url );
			
	signals:
		/*!
		* Emitted when the user clicked on the link, before the page changed.
		* If linkClicked() sets follow_link to false, the current page should NOT change.
		* Otherwise it should be changed to the new link value.
		*/
		void	linkClicked ( const QString & newlink, bool& follow_link );
	
	private slots:
		virtual void	onAnchorClicked ( const QUrl& url);
		
	private:
		// Overloaded to provide custom context menu
		void 			contextMenuEvent( QContextMenuEvent *e );
		
		void			find( bool forward, bool backward );
		
		QMenu * 		createPopupMenu ( const QPoint & pos );
		
		// Overriden to change the source
		void			setSource ( const QUrl & name );
		
		// Overriden to load resources
		QVariant 		loadResource ( int type, const QUrl & name );
				
		int				m_zoomfactor;
		bool			m_allowSourceChange;
	
		// Search data
		QString			m_searchText;
		int 	m_flags;
};


#endif /* KCHMVIEWWINDOW_QTEXTBROWSER_H */
