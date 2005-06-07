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

#ifndef KCHMVIEWWINDOW_KHTMLPART_H
#define KCHMVIEWWINDOW_KHTMLPART_H

#include "kde-qt.h"

#include "kchmviewwindow.h"
#include "kchmsourcefactory.h"

/**
@author Georgy Yunaev
*/
/*
 * For Qt-only version, we cannot compile KCHMViewWindow_KHTMLPart. However,
 * we cannot just exclude it, because it would not generate a MOC file for a KDE
 * version. Therefore we declare it, and compile the .moc file, but do not provide
 * the class methods.
 */
#if defined (USE_KDE)
class KCHMViewWindow_KHTMLPart : public KHTMLPart, public KCHMViewWindow
{
Q_OBJECT
public:
	KCHMViewWindow_KHTMLPart( QWidget * parent );
	~KCHMViewWindow_KHTMLPart();

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

	//! Initiates the find-in-page search, if succeed, cursor moved to the first entry
	virtual void	searchWord( const QString & word, bool forward = true, bool casesensitive = false );

	//! Select the content of the whole page
	virtual void	clipSelectAll();

	//! Copies the selected content to the clipboard
	virtual void	clipCopy();
	
	/*!
	 * Return current scrollbar position in view window. Saved on program exit. 
	 * There is no restriction on returned value, except that giving this value to 
	 * setScrollbarPosition() should move the scrollbar in the same position.
	 */
	virtual int		getScrollbarPosition();
	
	//! Sets the scrollbar position.
	virtual void	setScrollbarPosition(int pos);

	virtual QObject *	getQObject() { return this; }

	virtual void	emitSignalHistoryAvailabilityChanged (bool enable_backward, bool enable_forward);

signals:
	/*!
	 * Emitted when the user clicked on the link, before the page changed.
 	 * If signalLinkClicked() sets follow_link to false, the current page should NOT change.
	 * Otherwise it should be changed to the new link value.
	 */
	void	signalLinkClicked ( const QString & newlink, bool& follow_link );
	void	signalHistoryAvailabilityChanged (bool enable_backward, bool enable_forward);

private slots:
	virtual void	slotLinkClicked ( const QString & newlink);
	virtual void	onOpenURLRequest( const KURL &, const KParts::URLArgs & );
	virtual void 	onPopupMenu   	( const QString & url, const QPoint & point );
	
private:
	void setSource ( const QString & name );
			
	int			m_zoomfactor;
	bool		m_searchForward;
	QString		m_searchText;
	
	KPopupMenu *m_contextMenu;
	
	const KCHMTextEncoding::text_encoding_t *	m_currentEncoding;
};

#endif /* USE_KDE */

#endif /* KCHMVIEWWINDOW_KHTMLPART_H */