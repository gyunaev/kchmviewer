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

#ifndef KCHMINDEXWINDOW_H
#define KCHMINDEXWINDOW_H


#include "kde-qt.h"
#include "ui_tab_index.h"


class KCHMIndexWindow : public QWidget, public Ui::TabIndex
{
	Q_OBJECT
	public:
		KCHMIndexWindow ( QWidget * parent = 0 );
	
		void	invalidate();
		void	search( const QString& index );
		
	private slots:
		void 	onTextChanged ( const QString & newvalue);
		void 	onReturnPressed ();
		void	onDoubleClicked ( QTreeWidgetItem * item, int column );
		void	onContextMenuRequested ( const QPoint &point );
		
	private:
		virtual void showEvent ( QShowEvent * );
		
		void	refillIndex();
		
		QMenu 			* 	m_contextMenu;	
		QTreeWidgetItem	*	m_lastSelectedItem;
		bool				m_indexListFilled;
};

#endif
