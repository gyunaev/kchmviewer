/**************************************************************************
 *  Kchmviewer - a portable CHM file viewer with the best support for     *
 *  the international languages                                           *
 *                                                                        *
 *  Copyright (C) 2004-2012 George Yunaev, kchmviewer@ulduzsoft.com       *
 *                                                                        *
 *  Please read http://www.kchmviewer.net/reportbugs.html if you want     *
 *  to report a bug. It lists things I need to fix it!                    *
 *                                                                        *
 *  This program is free software: you can redistribute it and/or modify  *
 *  it under the terms of the GNU General Public License as published by  *
 *  the Free Software Foundation, either version 3 of the License, or     *
 *  (at your option) any later version.                                   *
 *																	      *
 *  This program is distributed in the hope that it will be useful,       *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *  GNU General Public License for more details.                          *
 *                                                                        *
 *  You should have received a copy of the GNU General Public License     *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 **************************************************************************/

#ifndef TREEVIEWITEM_H
#define TREEVIEWITEM_H

#include <QVector>
#include <QPixmap>
#include <QListWidget>
#include <QTreeWidget>
#include <QTableWidget>

class EBookIndexEntry;

//! This is a list item used both in Index and Table Of Content trees
class IndexTocItem : public QTreeWidgetItem
{
	public:
		IndexTocItem( QTreeWidgetItem* parent, QTreeWidgetItem* after, const QString& name, const QString& aurl, int image);
		IndexTocItem( QTreeWidget* parent, QTreeWidgetItem* after, const QString& name, const QString& url, int image);
		
		QString			getUrl() const;
	
		// Overridden methods
		int 			columnCount () const;
		QVariant 		data ( int column, int role ) const;
		
	private:
		QString		m_name;
		QString		m_url;
		int 		m_image_number;
};



void kchmFillListViewWithParsedData( QTreeWidget * list, const QList< EBookIndexEntry >& data, QMap<QString, IndexTocItem*> * map );

#endif
