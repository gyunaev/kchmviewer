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
#ifndef KCHMBOOKMARKWINDOW_H
#define KCHMBOOKMARKWINDOW_H

#include <qwidget.h>
#include <qvector.h>
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

	void	restoreSettings (const KCHMSettings::bookmark_saved_settings_t& settings);
	void	saveSettings (KCHMSettings::bookmark_saved_settings_t& settings);
	void	invalidate();
	
public slots:
	void 	onAddBookmarkPressed ();
	
private slots:
	void	onDelBookmarkPressed( );
	void	onEditBookmarkPressed( );
	void	onDoubleClicked ( QListViewItem *, const QPoint &, int );

private:
	QListView				*	m_bookmarkList;
	QString						m_bookmarkFileName;
	bool						m_listChanged;
};

#endif
