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

#ifndef KCHMVIEWWINDOW_H
#define KCHMVIEWWINDOW_H

#include "forwarddeclarations.h"
#include "kde-qt.h"
//Added by qt3to4:
#include <Q3ValueList>

/**
@author Georgy Yunaev
*/
class KCHMViewWindow
{
public:
	KCHMViewWindow ( QTabWidget * parent );
    virtual ~KCHMViewWindow();

	//! Open a page from current chm archive
	bool	openUrl (const QString& url );
	
	QString	getBaseUrl() const	{ return m_base_url; }
	QString	getOpenedPage() const	{ return m_openedPage; }
	QString	getNewTabLink() const	{ return m_newTabLinkKeeper; }
	QString	makeURLabsolute ( const QString &url, bool set_as_base = true );
	
public: 
	// virtual members, which should be implemented by viewers
	//! Invalidate current view, doing all the cleanups etc.
	virtual void	invalidate();

	//! Popups the print dialog, and prints the current page on the printer.
	virtual bool	printCurrentPage() = 0;

	//! Continues the find-in-page search forward or backward
	virtual void	searchWord( const QString & word, bool forward = true, bool casesensitive = false ) = 0;

	//! Return current ZoomFactor.
	virtual int		getZoomFactor() const = 0;
	
	//! Sets ZoomFactor. The value returned by getZoomFactor(), given to this function, should give the same result.
	virtual void	setZoomFactor (int zoom) = 0;
	
	//! Relatively changes ZoomFactor. Most common values are -1 and 1.
	virtual void	addZoomFactor (int value) = 0;

	virtual QObject *	getQObject() = 0;
	virtual QWidget *	getQWidget() = 0;

	/*!
	 * Return current scrollbar position in view window. Saved on program exit. 
	 * There is no restriction on returned value, except that giving this value to 
	 * setScrollbarPosition() should move the scrollbar in the same position.
	 */
	virtual int		getScrollbarPosition() = 0;
	
	//! Sets the scrollbar position.
	virtual void	setScrollbarPosition(int pos) = 0;

	//! Select the content of the whole page
	virtual void	clipSelectAll() = 0;

	//! Copies the selected content to the clipboard
	virtual void	clipCopy() = 0;

	//! Returns the window title
	virtual QString	getTitle() const;
	
	//! Navigation stuff
	virtual void	navigateBack();
	virtual void	navigateHome();
	virtual void	navigateForward();
	
	//! Navigation auxiliary stuff
	virtual void	setHistoryMaxSize (unsigned int size) { m_historyMaxSize = size; }
	virtual void	addNavigationHistory( const QString & url, int scrollpos );
	virtual void 	updateNavigationToolbar();
	
	/*! 
	 * Used by contents window (and probably by other windows in future) to show
	 * context menu in listviews. Put here to futher reuse code in index and search windows.
	 */
	KQMenu *	createListItemContextMenu ( QWidget * w );
	void			setTabKeeper ( const QString& link );
	
		
protected: /* signals */
	/*!
	 * Emitted when the user clicked on the link, before the page changed.
	 * If linkClicked() return false, the current page should NOT change.
	 * Otherwise it should be changed to the new link value.
	 */
	virtual void	signalLinkClicked ( const QString & newlink, bool& follow_link ) = 0;

protected:
	virtual bool	openPage ( const QString& url ) = 0;
	virtual void	handleStartPageAsImage( QString& link );
	
	KQMenu * 	getContextMenu( const QString& link, QWidget * parent );
	KQMenu * 	createStandardContextMenu( QWidget * parent );
	
	//! History
	class KCHMUrlHistory
	{
		public:
			KCHMUrlHistory() { scrollbarpos = 0; }
			KCHMUrlHistory( const QString& _url, int _scrollbarpos )
			: url(_url), scrollbarpos(_scrollbarpos) {};
		
			const QString&  getUrl() const { return url; }
			int 			getScrollPosition() const { return scrollbarpos; }
			void			setScrollPosition( int pos ) { scrollbarpos = pos; }
			
		private:
			QString  	url;
			int 		scrollbarpos;
	};

	unsigned int	m_historyMaxSize;
	unsigned int	m_historyCurrentPos;
	
	Q3ValueList<KCHMUrlHistory>		m_history;
	
	KQMenu *	m_contextMenu;
	KQMenu *	m_contextMenuLink;
	
	// This member keeps a "open new tab" link between getContextMenu() call and appropriate
	// slot call
	QString			m_newTabLinkKeeper;

	QString 		m_openedPage;
	QString 		m_lastOpenedPage;
	QString			m_base_url;

	QTabWidget	*	m_parentTabWidget;
};

#endif
