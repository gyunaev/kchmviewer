/***************************************************************************
 *   Copyright (C) 2004-2005 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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
#ifndef KCHMBOOKMARKWINDOW_H
#define KCHMBOOKMARKWINDOW_H

#include "kde-qt.h"
#include "forwarddeclarations.h"
#include "kchmsettings.h"

/**
@author Georgy Yunaev
*/
class KCHMBookmarkWindow : public QWidget
{
Q_OBJECT
public:
    KCHMBookmarkWindow(QWidget *parent = 0, const char *name = 0);
	virtual ~KCHMBookmarkWindow() {};

	void 	createMenu( KCHMMainWindow * parent );
	
	void	restoreSettings (const KCHMSettings::bookmark_saved_settings_t& settings);
	void	saveSettings (KCHMSettings::bookmark_saved_settings_t& settings);
	void	invalidate();
	
public slots:
	void 	onAddBookmarkPressed ();
	void	slotContextMenuRequested ( QListViewItem *item, const QPoint &point, int column );
		
private slots:
	void	onBookmarkSelected( int );
	void	onDelBookmarkPressed( );
	void	onEditBookmarkPressed( );
	void	onDoubleClicked ( QListViewItem *, const QPoint &, int );

private:
	KQPopupMenu *	m_menuBookmarks;
	KQListView	*	m_bookmarkList;
	QString			m_bookmarkFileName;
	bool			m_listChanged;
	KQPopupMenu * 	m_contextMenu;		
};

#endif
