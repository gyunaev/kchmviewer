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

#ifndef KCHMVIEWWINDOW_H
#define KCHMVIEWWINDOW_H

#include "forwarddeclarations.h"
#include "kde-qt.h"

/**
@author Georgy Yunaev
*/
class KCHMViewWindow
{
public:
	KCHMViewWindow ( QWidget * parent );
    virtual ~KCHMViewWindow();

	//! Open a page from current chm archive
	bool	openUrl (const QString& url, bool addHistory = true);
	
	QString	getBaseUrl() const	{ return m_base_url; }
	QString	getOpenedPage() const	{ return m_openedPage; }

	//! true if url is remote (http/ftp/mailto/news etc.)
	static bool	isRemoteURL (const QString& url, QString& protocol);
	
	//! true if url is javascript:// URL
	static bool	isJavascriptURL (const QString& url);
	
	//! true if url is a different CHM url, return new chm file and the page.
	static bool	isNewChmURL (const QString& url, QString& chmfile, QString& page);

	//! Making URL absolute
	static QString makeURLabsoluteIfNeeded ( const QString & url );
	QString		makeURLabsolute ( const QString &url, bool set_as_base = true );
	
	void		navigateBack();
	void		navigateForward();

	void		setHistoryMaxSize (unsigned int size) { m_historyMaxSize = size; }

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

	/*!
	 * Return current scrollbar position in view window. Saved on program exit. 
	 * There is no restriction on returned value, except that giving this value to 
	 * setScrollbarPosition() should move the scrollbar in the same position.
	 */
	virtual int		getScrollbarPosition() = 0;
	
	//! Sets the scrollbar position.
	virtual void	setScrollbarPosition(int pos) = 0;

	//! Should emit this signal (because KCHMViewWindow is not QObject derived)
	virtual void	emitSignalHistoryAvailabilityChanged (bool enable_backward, bool enable_forward) = 0;

protected: /* signals */
	/*!
	 * Emitted when the user clicked on the link, before the page changed.
	 * If linkClicked() return false, the current page should NOT change.
	 * Otherwise it should be changed to the new link value.
	 */
	virtual void	signalLinkClicked ( const QString & newlink, bool& follow_link ) = 0;

	/*!
	 * Emitted when the backward/forward button status changed. Can be connected to enable/disable
	 * appropriate toolbar buttons and/or menu items.
	 */
	virtual void	signalHistoryAvailabilityChanged (bool enable_backward, bool enable_forward) = 0;

protected:
	//! Sets the scrollbar position.
	virtual bool	openPage ( const QString& url ) = 0;

	virtual void	checkHistoryAvailability ();

	QString 				m_openedPage;
	QString					m_base_url;

	unsigned int			m_historyMaxSize;
	unsigned int			m_historyCurrentSize;
	unsigned int			m_historyTopOffset;
	QValueList<QString>		m_history;
	QValueList<QString>::iterator m_historyIterator;
};

#endif
