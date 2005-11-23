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
#ifndef KCHMINDEXWINDOW_H
#define KCHMINDEXWINDOW_H


#include <qlineedit.h>
#include <qlistview.h>


/**
@author Georgy Yunaev
*/
class KCHMIndexWindow : public QWidget
{
Q_OBJECT
public:
    KCHMIndexWindow ( QWidget * parent = 0, const char * name = 0, WFlags f = 0 );

	void	invalidate();
	
private slots:
	void 	onTextChanged ( const QString & newvalue);
	void 	onReturnPressed ();
	void	onDoubleClicked ( QListViewItem *, const QPoint &, int);

private:
	virtual void showEvent ( QShowEvent * );
	
	QLineEdit 	*	m_indexFinder;
	QListView	*	m_indexList;
	QListViewItem * m_lastSelectedItem;
	bool			m_indexListFilled;
};

#endif
