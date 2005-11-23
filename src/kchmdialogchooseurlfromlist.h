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
#ifndef KCHMDIALOGCHOOSEURLFROMLIST_H
#define KCHMDIALOGCHOOSEURLFROMLIST_H

#include <qdialog.h>
#include <qlistview.h>

/**
@author tim
*/
class KCHMDialogChooseUrlFromList : public QDialog
{
Q_OBJECT
public:
    KCHMDialogChooseUrlFromList (const QStringList& urls, const QStringList& titles, QWidget* parent);
	QString getSelectedItemUrl()	{ return m_acceptedurl; }

private slots:
	void onDoubleClicked( QListViewItem * item, const QPoint &, int );
	void onCurrentChanged ( QListViewItem * item);

private:
	QListView *	m_urlsList;
	QString		m_acceptedurl;
};

#endif
