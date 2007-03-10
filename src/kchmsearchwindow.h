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

#ifndef KCHMSEARCHWINDOW_H
#define KCHMSEARCHWINDOW_H

#include "kde-qt.h"

#include "kchmsettings.h"
#include "forwarddeclarations.h"


/**
@author Georgy Yunaev
*/
class KCHMSearchEngine;


class KCHMClickableLabel : public QLabel
{
	Q_OBJECT
	public:
		KCHMClickableLabel( const QString& label, QWidget * parent )
	: QLabel( label, parent ) {};
		
		virtual ~KCHMClickableLabel() {};
				
	signals:
		void	clicked();
						
	protected:
		virtual void mousePressEvent ( QMouseEvent * ) 	{ emit clicked(); }
};


class KCHMSearchWindow : public QWidget
{
	Q_OBJECT
	public:
		KCHMSearchWindow ( QWidget * parent = 0, const char * name = 0, WFlags f = 0 );
	
		void	invalidate();
		void	restoreSettings (const KCHMSettings::search_saved_settings_t& settings);
		void	saveSettings (KCHMSettings::search_saved_settings_t& settings);
	
	public slots:
		void	slotContextMenuRequested ( QListViewItem *item, const QPoint &point, int column );
		
	private slots:
		void	onHelpClicked();
		void 	onReturnPressed ();
		void	onDoubleClicked ( QListViewItem *, const QPoint &, int);
	
	private:
		bool	initSearchEngine();
		
	private:
		QComboBox 		*	m_searchQuery;
		KQListView		*	m_searchList;
		KQPopupMenu		* 	m_contextMenu;
		
		KCHMSearchEngine*	m_searchEngine;
};

#endif
