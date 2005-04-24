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

#include "kde-qt.h"

#if defined (USE_KDE)
	#include <khtmlview.h>
	#include <khtml_part.h>
#else
	#include <qtextbrowser.h>
#endif

#include "xchmfile.h"
#include "kchmsourcefactory.h"

/**
@author Georgy Yunaev
*/
#if defined (USE_KDE)
class KCHMViewWindow : public KHTMLPart
#else
class KCHMViewWindow : public QTextBrowser
#endif
{
public:
    KCHMViewWindow( QWidget * parent = 0, bool resolve_images = true );
    ~KCHMViewWindow();

	bool	LoadPage (QString url);
	void	setSource ( const QString & name );
	void	denyNextSourceChange ()	{ m_shouldSkipSourceChange = true; }
	void	invalidate();

	int		getZoomFactor() const	{	return m_zoomfactor; }
	void	setZoomFactor (int zoom);
	void	zoomIn ();
	void	zoomOut();
	
	QString	getBaseUrl() const	{ return m_base_url; }
	QString	getOpenedPage() const	{ return m_openedPage; }

	static bool	isRemoteURL (const QString& url, QString& protocol);
	static bool	isJavascriptURL (const QString& url);
	static bool	isNewChmURL (const QString& url, QString& chmfile, QString& page);

	static QString makeURLabsoluteIfNeeded ( const QString & url );

	QString		makeURLabsolute ( const QString &url, bool set_as_base = true );
	bool		areImagesResolved() { return m_resolveImages; }

	int		getScrollbarPosition();
	void	setScrollbarPosition(int pos);

	void	navBackward();
	void	navForward();

	void	clearWindow();

private:
	KCHMSourceFactory	*	m_sourcefactory;
	bool					m_shouldSkipSourceChange;	
	int						m_zoomfactor;
	QString					m_base_url;
	QString 				m_openedPage;
	bool					m_resolveImages;
};

#endif
