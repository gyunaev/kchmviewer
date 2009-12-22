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

#ifndef VIEWWINDOW_KHTMLPART_H
#define VIEWWINDOW_KHTMLPART_H

#include <kurl.h>
#include "kde-qt.h"

#include "viewwindow.h"
#include "libchmtextencoding.h"


/**
@author Georgy Yunaev
 */
class ViewWindow_KHTMLPart : public KHTMLPart, public ViewWindow
{
	Q_OBJECT
	public:
		ViewWindow_KHTMLPart( ViewWindowTabs * parent );
		~ViewWindow_KHTMLPart();
	
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
		virtual QWidget *	getQWidget();
	
	signals:
		/*!
		* Emitted when the user clicked on the link, before the page changed.
		* If linkClicked() sets follow_link to false, the current page should NOT change.
		* Otherwise it should be changed to the new link value.
		*/
		void	linkClicked ( const QString & newlink, bool& follow_link );
	
	private slots:
		virtual void	slotLinkClicked ( const QString & newlink);
		virtual void	onOpenURLRequest( const KUrl &, const KParts::OpenUrlArguments &, const KParts::BrowserArguments&  );
		virtual void 	onPopupMenu   	( const QString & url, const QPoint & point );
		
	private:
		void setSource ( const QString & name );
				
		int			m_zoomfactor;
		
		const LCHMTextEncoding *	m_currentEncoding;
};

#endif /* VIEWWINDOW_KHTMLPART_H */