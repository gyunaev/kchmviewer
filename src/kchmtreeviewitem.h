/***************************************************************************
 *   Copyright (C) 2004-2007 by Georgy Yunaev, gyunaev@ulduzsoft.com       *
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
		KCHMIndTocItem( QTreeWidgetItem* parent, QTreeWidgetItem* after, QString name, QString aurl, int image); 
		KCHMIndTocItem( QTreeWidget* parent, QTreeWidgetItem* after, QString name, QString url, int image);
		
		QString			getUrl() const;
	
		// Overridden methods
		void 			setExpanded ( bool open );
		int 			columnCount () const;
		QVariant 		data ( int column, int role ) const;
		
	private:
		// FIXME: painting!
		//virtual void paintBranches ( QPainter * p, const QColorGroup & cg, int w, int y, int h );
		//virtual void paintCell ( QPainter * p, const QColorGroup & cg, int column, int width, int align );
			
		QString		m_name;
		QString		m_url;
		int 		m_image_number;
};



class KCMSearchTreeViewItem : public QTableWidgetItem
{
	public:
		// FIXME: check that QString is const QString& everywhere
		KCMSearchTreeViewItem( const QString& name, const QString& loc, const QString& url );
		QString		getUrl() const;
		
	protected:
		// Overriden members
		int columnCount () const;
		
		// Overriden member
		QVariant data ( int column, int role ) const; 
		
	private:
		QString		m_url;
		QString		m_name;
		QString		m_loc;
};



class KCHMSingleTreeViewItem : public QListWidgetItem
{
	public:
		KCHMSingleTreeViewItem( QListWidget* parent, QString name, QString url )
			: QListWidgetItem( parent )
		{
			setText( name );
			this->url = url;
		}
	
		QString		getUrl() const	{ return url; }
		
	private:
		QString		url;
};


void kchmFillListViewWithParsedData( QTreeWidget * list, const QVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map );

#endif
