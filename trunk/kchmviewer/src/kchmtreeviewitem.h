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

#ifndef CTREEVIEWITEM_H
#define CTREEVIEWITEM_H

#include <qlistview.h>
#include <qvaluevector.h>

#include "libchmfile.h"

/**
@author Georgy Yunaev
*/
//! This is a list item used both in Index and Table Of Content trees
class KCHMIndTocItem : public QListViewItem
{
	public:
		KCHMIndTocItem( QListViewItem* parent, QListViewItem* after, QString name, QString aurl, int image); 
		KCHMIndTocItem( QListView* parent, QListViewItem* after, QString name, QString url, int image);
		
		QString		getUrl() const;
		virtual void setOpen ( bool open );
		
	private:
		virtual void paintBranches ( QPainter * p, const QColorGroup & cg, int w, int y, int h );
		virtual void paintCell ( QPainter * p, const QColorGroup & cg, int column, int width, int align );
		virtual const QPixmap * pixmap( int i ) const;
		
		QString		url;
		int 		image_number;
};


class KCMSearchTreeViewItem : public QListViewItem
{
	public:
		KCMSearchTreeViewItem (QListView* parent, QString name, QString loc, QString url)
			: QListViewItem (parent, name, loc)
		{
			this->url = url;
		}
	
		QString		getUrl() const	{ return url; }
		
	private:
		QString		url;
};


class KCHMSingleTreeViewItem : public QListViewItem
{
	public:
		KCHMSingleTreeViewItem (QListView* parent, QString name, QString url)
			: QListViewItem (parent, name)
		{
			this->url = url;
		}
	
		QString		getUrl() const	{ return url; }
		
	private:
		QString		url;
};


class KCHMBookmarkTreeViewItem : public QListViewItem
{
	public:
		KCHMBookmarkTreeViewItem (QListView* parent, QString n, QString u, int s)
			: QListViewItem (parent, n), url(u), name(n), scroll_y(s) {	menuid = 0; }
	
		QString		url;
		QString		name;
		int			scroll_y;
		int			menuid;
};


void kchmFillListViewWithParsedData( QListView * list, const QValueVector< LCHMParsedEntry >& data, QMap<QString, KCHMIndTocItem*> * map );

#endif
