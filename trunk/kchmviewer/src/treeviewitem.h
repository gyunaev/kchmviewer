/**************************************************************************
 *  Kchmviewer - a CHM file viewer with broad language support            *
 *  Copyright (C) 2004-2010 George Yunaev, kchmviewer@ulduzsoft.com       *
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

#ifndef KCHMTREEVIEWITEM_H
#define KCHMTREEVIEWITEM_H

#include <QVector>
#include <QPixmap>
#include <QListWidget>
#include <QTreeWidget>
#include <QTableWidget>

#include "libchmfile.h"


//! This is a list item used both in Index and Table Of Content trees
class KCHMIndTocItem : public QTreeWidgetItem
{
	public:
		KCHMIndTocItem( QTreeWidgetItem* parent, QTreeWidgetItem* after, const QString& name, const QString& aurl, int image); 
		KCHMIndTocItem( QTreeWidget* parent, QTreeWidgetItem* after, const QString& name, const QString& url, int image);
		
		QString			getUrl() const;
	
		// Overridden methods
		int 			columnCount () const;
		QVariant 		data ( int column, int role ) const;
		
	private:
		QString		m_name;
		QString		m_url;
		int 		m_image_number;
};



void kchmFillListViewWithParsedData( QTreeWidget * list, const QVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map );

#endif
